/**
 * Internal service-to-service API (/api/internal).
 *
 * Mounted behind internalAuth (X-Internal-Secret). Used by trusted services
 * (e.g. the 3D Estimator) to do things that would be a violation to expose to a
 * browser / end user over the public API:
 *
 *   GET /api/internal/tenants/:businessDbName/dek
 *       Resolve a tenant Admin by its estimatorBusinessDbName and unwrap its
 *       DEK. Preferred path is the in-memory passkey session (no Vault round
 *       trip); the Vault Transit recovery path (recoverDEK) is the rare
 *       fallback. Every call is audited as 'internal_api' with the calling
 *       service recorded from the required X-Calling-Service header.
 *
 *   GET /api/internal/embed-keys/:key/validate
 *       Exposes the embed-key resolution logic (1.4) as a plain endpoint so
 *       other services can validate an embed key directly.
 *
 * Defense in depth: in production this router must ALSO be firewalled at the
 * network level (localhost / internal network only) — never publicly routable.
 */
import { Router } from 'express';
import internalAuth from '../middlewares/internalAuth.js';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import AuditLog from '../models/AuditLog.js';
import { getTenantDEK, recoverDEK } from '../services/tenantCrypto.js';
import { resolveEmbedKey } from '../middlewares/embedKeyAuth.js';

const router = Router();
router.use(internalAuth);

// Placeholder actor for system-level audit records where no admin resolves.
const PLACEHOLDER_ACTOR = '000000000000000000000000';
// estimatorBusinessDbName is derived at provisioning time (superAdminController):
const ESTIMATOR_DB_PREFIX = 'estimator_';

const getCallingService = (req) => {
  const value = req.headers['x-calling-service'];
  return typeof value === 'string' && value.trim() ? value.trim() : null;
};

const writeInternalAudit = async ({ req, action, adminId = null, callingService = null, metadata = {} }) => {
  try {
    const entry = {
      actorId: PLACEHOLDER_ACTOR,
      actorRole: 'system',
      action,
      actionCategory: 'internal_api',
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: {
        ...metadata,
        callingService: callingService ? String(callingService) : '',
        endpoint: `${req.method} ${req.originalUrl || req.url}`
      }
    };
    if (adminId) {
      entry.targetType = 'admin';
      entry.targetId = adminId;
      entry.tenantAdminId = adminId;
    }
    await AuditLog.create(entry);
  } catch (err) {
    console.error(`[Internal] Audit write failed (${action}):`, err.message);
  }
};

/**
 * Resolve an Admin or SuperAdmin by its derived estimatorBusinessDbName
 * (e.g. 'estimator_abc-steel-buildings-2', 'abc-steel-buildings-2', an ObjectId, or 'api').
 */
async function resolveAdminByBusinessDbName(businessDbName) {
  if (!businessDbName || typeof businessDbName !== 'string') return null;

  if (businessDbName === 'api') {
    const rootSa = await SuperAdmin.findOne({ role: 'root' })
      .select('_id subdomain wrappedDataKey wrappedDataKeyKMS')
      .lean();
    if (rootSa) return rootSa;
  }

  // Direct ObjectId lookup
  if (/^[0-9a-f]{24}$/i.test(businessDbName)) {
    let entity = await Admin.findById(businessDbName)
      .select('_id subdomain wrappedDataKey wrappedDataKeyKMS')
      .lean();
    if (!entity) {
      entity = await SuperAdmin.findById(businessDbName)
        .select('_id subdomain wrappedDataKey wrappedDataKeyKMS')
        .lean();
    }
    if (entity) return entity;
  }

  const subdomain = businessDbName.startsWith(ESTIMATOR_DB_PREFIX)
    ? businessDbName.slice(ESTIMATOR_DB_PREFIX.length)
    : businessDbName;
  if (!subdomain) return null;

  let admin = await Admin.findOne({ subdomain })
    .select('_id subdomain wrappedDataKey wrappedDataKeyKMS')
    .lean();

  if (!admin) {
    admin = await SuperAdmin.findOne({ subdomain })
      .select('_id subdomain wrappedDataKey wrappedDataKeyKMS')
      .lean();
  }

  if (!admin) return null;
  return admin;
}

/**
 * @desc Unwrap a tenant's DEK for another trusted service.
 * @route GET /api/internal/tenants/:businessDbName/dek
 * @access Internal service (X-Internal-Secret) + X-Calling-Service
 * @returns { success, data: { adminId, businessDbName, dek, unwrapPath } }
 */
router.get('/tenants/:businessDbName/dek', async (req, res, next) => {
  try {
    const callingService = getCallingService(req);
    if (!callingService) {
      return res.status(400).json({ success: false, message: 'X-Calling-Service header is required' });
    }
    const { businessDbName } = req.params;

    const admin = await resolveAdminByBusinessDbName(businessDbName);
    if (!admin) {
      await writeInternalAudit({ req, action: 'internal.dek.get', callingService, metadata: { businessDbName, status: 'not_found' } });
      return res.status(404).json({ success: false, message: 'No tenant found for the given business database name' });
    }

    const adminId = admin._id.toString();

    // Preferred: passkey session in this server's memory (no Vault round trip).
    let dek = admin.wrappedDataKey ? getTenantDEK(adminId, admin.wrappedDataKey) : null;
    let unwrapPath = dek ? 'passkey-session' : null;

    // Vault Transit recovery / on-demand provisioning path.
    if (!dek) {
      try {
        dek = await recoverDEK(adminId, `internal.dek.get (${callingService})`, {
          id: PLACEHOLDER_ACTOR,
          role: 'system',
          ip: req.ip || undefined
        });
        unwrapPath = 'vault-recovery';
      } catch (err) {
        console.error(`[Internal] Vault recovery failed for ${adminId}:`, err.message);
      }
    }

    if (!dek || !unwrapPath) {
      await writeInternalAudit({
        req, action: 'internal.dek.get', adminId, callingService,
        metadata: { businessDbName, status: 'dek_unavailable' }
      });
      return res.status(409).json({ success: false, message: 'DEK unavailable for this tenant (onboard encryption or supply a passkey session first).' });
    }

    console.log(`[Internal] DEK served for ${adminId} (${businessDbName}) via ${unwrapPath}`);
    await writeInternalAudit({
      req, action: 'internal.dek.get', adminId, callingService,
      metadata: { businessDbName, status: 'ok', unwrapPath }
    });

    return res.json({ success: true, data: { adminId, businessDbName, dek: dek.toString('base64'), unwrapPath } });
  } catch (err) {
    next(err);
  }
});

/**
 * @desc Validate an embed key (1.4 logic) as a plain internal endpoint.
 * @route GET /api/internal/embed-keys/:key/validate
 * @access Internal service (X-Internal-Secret)
 * @returns { success, valid, adminId, businessDbName }
 */
router.get('/embed-keys/:key/validate', async (req, res, next) => {
  try {
    let key = req.params.key;
    if (key && typeof key === 'string') key = decodeURIComponent(key);

    const result = await resolveEmbedKey(key, 'internal');

    await writeInternalAudit({
      req, action: 'internal.embed_key.validate',
      adminId: result.valid ? result.adminId : null,
      callingService: getCallingService(req),
      metadata: { status: result.valid ? 'valid' : result.reason }
    });

    if (!result.valid) {
      return res.json({ success: true, valid: false, adminId: null, superAdminId: null, businessDbName: null });
    }
    return res.json({
      success: true,
      valid: true,
      adminId: result.adminId || null,
      superAdminId: result.superAdminId || null,
      businessDbName: result.businessDbName || 'api'
    });
  } catch (err) {
    next(err);
  }
});

export default router;
