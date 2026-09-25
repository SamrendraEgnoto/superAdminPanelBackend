import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import AuditLog from '../models/AuditLog.js';

// Placeholder actor for system-level audit records where no admin resolves.
const PLACEHOLDER_ACTOR = '000000000000000000000000';

// Extract the embed key from header (canonical), then query/body fallbacks.
const extractKey = (req) =>
  (req.headers && req.headers['x-embed-key']) ||
  (req.headers && req.headers['x-tenant-key']) ||
  (req.query && (req.query.key || req.query.tenant || req.query.tenantId || req.query.embedKey)) ||
  (req.body && (req.body.key || req.body.tenant || req.body.tenantId || req.body.embedKey)) ||
  null;

const maskKey = (key) => (key ? `${String(key).slice(0, 20)}...` : null);

const writeAudit = async ({ req, action, key, adminId, reason = null }) => {
  try {
    await AuditLog.create({
      actorId: adminId || PLACEHOLDER_ACTOR,
      actorRole: 'system',
      action,
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: adminId || undefined,
      ipAddress: req.ip || (req.headers && req.headers['x-forwarded-for']) || 'unknown',
      metadata: {
        key: maskKey(key),
        reason: reason || ''
      }
    });
  } catch (err) {
    console.error(`[EmbedKeyAuth] Failed to write audit (${action}):`, err.message);
  }
};

const deriveBusinessDbName = (admin) =>
  admin && admin.subdomain ? `estimator_${admin.subdomain}` : null;

/**
 * Resolve and validate an embed key without express req/res plumbing.
 * Shared by the embed-key middleware and the internal validate endpoint.
 * Supports both Admin and Delegated SuperAdmin embed keys.
 *
 * @param {string} key embed key (x-embed-key value or direct tenant ID)
 * @param {string} [origin] origin for lastUsedOrigin bookkeeping
 * @returns {{valid:false, reason:string, adminId?:string}|{valid:true, adminId:string, superAdminId:string, isSuperAdmin:boolean, scope:string, businessDbName:string}}
 */
export async function resolveEmbedKey(key, origin = 'unknown') {
  if (!key) return { valid: false, reason: 'missing_key' };

  const rawKey = String(key).trim();
  const cleanKey = rawKey.replace(/\.+$/, '').trim();

  // 1. Direct exact match on embedKeys.key
  let entity = await Admin.findOne({ 'embedKeys.key': rawKey });
  let isSuperAdmin = false;
  if (!entity) {
    entity = await SuperAdmin.findOne({ 'embedKeys.key': rawKey });
    if (entity) isSuperAdmin = true;
  }

  // 2. Prefix match if cleanKey was truncated (e.g. copied preview ending in ...)
  if (!entity && cleanKey && cleanKey.length >= 15) {
    const escaped = cleanKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    entity = await Admin.findOne({ 'embedKeys.key': new RegExp('^' + escaped) });
    if (!entity) {
      entity = await SuperAdmin.findOne({ 'embedKeys.key': new RegExp('^' + escaped) });
      if (entity) isSuperAdmin = true;
    }
  }

  // 3. Fallback: Check if key is a valid 24-hex ObjectId
  if (!entity && /^[0-9a-f]{24}$/i.test(cleanKey)) {
    entity = await SuperAdmin.findById(cleanKey);
    if (entity) {
      isSuperAdmin = true;
    } else {
      entity = await Admin.findById(cleanKey);
    }
    if (entity) {
      const entityId = entity._id.toString();
      return {
        valid: true,
        adminId: isSuperAdmin ? null : entityId,
        superAdminId: isSuperAdmin ? entityId : (entity.createdById || entity.createdBy || null),
        isSuperAdmin,
        scope: 'create-lead-only',
        businessDbName: deriveBusinessDbName(entity) || 'api'
      };
    }
  }

  // 4. Fallback: Match by subdomain (e.g. "abc", "nikhil-dev")
  if (!entity && cleanKey) {
    const sub = cleanKey.toLowerCase();
    entity = await Admin.findOne({ subdomain: sub });
    if (!entity) {
      entity = await SuperAdmin.findOne({ subdomain: sub });
      if (entity) isSuperAdmin = true;
    }
    if (entity) {
      const entityId = entity._id.toString();
      return {
        valid: true,
        adminId: isSuperAdmin ? null : entityId,
        superAdminId: isSuperAdmin ? entityId : (entity.createdById || entity.createdBy || null),
        isSuperAdmin,
        scope: 'create-lead-only',
        businessDbName: deriveBusinessDbName(entity) || 'api'
      };
    }
  }

  // 5. Fallback: Match by companyName (case-insensitive)
  if (!entity && cleanKey) {
    const escapedComp = cleanKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    entity = await Admin.findOne({ companyName: new RegExp('^' + escapedComp + '$', 'i') });
    if (entity) {
      const entityId = entity._id.toString();
      return {
        valid: true,
        adminId: entityId,
        superAdminId: entity.createdById || entity.createdBy || null,
        isSuperAdmin: false,
        scope: 'create-lead-only',
        businessDbName: deriveBusinessDbName(entity) || 'api'
      };
    }
  }

  if (!entity) return { valid: false, reason: 'unknown_key' };

  // Find the matching embed key entry
  const entry = (entity.embedKeys || []).find((k) =>
    k.key === rawKey || (cleanKey && k.key && k.key.startsWith(cleanKey))
  );
  const entityId = entity._id.toString();

  if (entry && entry.revokedAt) return { valid: false, reason: 'revoked', adminId: entityId, isSuperAdmin };
  if (entry && entry.expiresAt && entry.expiresAt.getTime() < Date.now()) {
    return { valid: false, reason: 'expired', adminId: entityId, isSuperAdmin };
  }

  // Successful use: record activity
  if (entry) {
    entry.lastUsedAt = new Date();
    entry.lastUsedOrigin = origin;
    await entity.save().catch(() => null);
  }

  return {
    valid: true,
    adminId: isSuperAdmin ? null : entityId,
    superAdminId: isSuperAdmin ? entityId : (entity.createdById || entity.createdBy || null),
    isSuperAdmin,
    scope: entry?.scope || 'create-lead-only',
    businessDbName: deriveBusinessDbName(entity) || 'api'
  };
}

// Per-key rate limiter: 60 requests / minute, keyed on the embed key.
const keyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const key = extractKey(req);
    if (key) return `embed:${key}`;
    return ipKeyGenerator(req);
  },
  handler: async (req, res, next) => {
    const key = extractKey(req);
    let adminId = null;
    if (key) {
      const found = await Admin.findOne({ 'embedKeys.key': key }).catch(() => null);
      if (found) adminId = found._id.toString();
    }
    await writeAudit({ req, action: 'embed_key.rejected', key, adminId, reason: 'rate_limit_exceeded' });
    res.status(429).json({ success: false, message: 'Too many requests. Rate limit exceeded.' });
  }
});

/**
 * Validate an embed key and resolve the owning admin.
 * - Rejects if the key is missing or unknown.
 * - Rejects if revokedAt is set or expiresAt has passed (grace rotation).
 * - Updates lastUsedAt / lastUsedOrigin on success.
 * - Attaches req.adminId (and req.embedKeyScope) for downstream handlers.
 * - Writes an audit entry for every accepted / rejected lookup.
 */
export default async function embedKeyAuth(req, res, next) {
  keyLimiter(req, res, async (err) => {
    if (err) return next(err);

    const key = extractKey(req);
    if (!key) {
      await writeAudit({ req, action: 'embed_key.rejected', key: null, adminId: null, reason: 'missing_key' });
      return res.status(401).json({ success: false, message: 'Embed key is required' });
    }

    try {
      const result = await resolveEmbedKey(key, req.headers.origin || req.ip || 'unknown');

      if (!result.valid) {
        await writeAudit({ req, action: 'embed_key.rejected', key, adminId: result.adminId || null, reason: result.reason });
        if (result.reason === 'revoked' || result.reason === 'expired') {
          return res.status(403).json({ success: false, message: `Embed key has been ${result.reason}` });
        }
        return res.status(401).json({ success: false, message: 'Invalid embed key' });
      }

      req.adminId = result.adminId;
      req.superAdminId = result.superAdminId;
      req.isSuperAdmin = result.isSuperAdmin;
      req.embedKeyScope = result.scope;

      await writeAudit({ req, action: 'embed_key.use', key, adminId: result.adminId || result.superAdminId });

      return next();
    } catch (e) {
      return next(e);
    }
  });
}

