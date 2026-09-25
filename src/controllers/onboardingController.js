import Admin from '../models/Admin.js';
import AuditLog from '../models/AuditLog.js';
import { generateDEK, wrapWithPasskey, wrapWithVault, setTenantPasskey, getTenantDEK } from '../services/tenantCrypto.js';

/**
 * POST /api/auth/onboarding/tenant  (authenticated admin)
 *
 * One-time tenant onboarding for envelope encryption. The admin supplies the
 * sender email they use for lead notifications and a passkey. We:
 *   1. generate a fresh 32-byte tenant DEK,
 *   2. wrap it with the passkey  (AES-256-GCM / PBKDF2) -> Admin.wrappedDataKey,
 *   3. wrap it with Vault Transit (KEK)              -> Admin.wrappedDataKeyKMS,
 *   4. discard the raw DEK + passkey (nothing persists except wrapped copies),
 *   5. place the passkey in the in-memory session store so this request and the
 *      admin's save encrypt using the tenant DEK.
 *
 * The Vault copy is ONLY used by the recovery path (recoverDEK + audit trail),
 * never for normal reads/writes. Re-running this replaces the wrapped copies
 * (rotate the passkey; existing ciphertext stays decryptable via Vault recovery
 * while the old DEK is rotated).
 */
export async function configureTenantPasskey(req, res, next) {
  try {
    const adminId = req.user.id;
    const { senderEmail, passkey } = req.body || {};

    if (!passkey || typeof passkey !== 'string') {
      return res.status(400).json({ success: false, message: 'A passkey is required to enable tenant encryption.' });
    }
    if (passkey.length < 8) {
      return res.status(400).json({ success: false, message: 'Passkey must be at least 8 characters long.' });
    }

    const admin = await Admin.findById(adminId);
    if (!admin) {
      return res.status(404).json({ success: false, message: 'Admin not found.' });
    }

    const dek = generateDEK();
    const wrappedWithPasskey = wrapWithPasskey(dek, passkey);
    const wrappedWithVault = await wrapWithVault(dek);

    admin.wrappedDataKey = JSON.stringify(wrappedWithPasskey);
    admin.wrappedDataKeyKMS = wrappedWithVault;
    if (senderEmail && typeof senderEmail === 'string') {
      admin.smtpSenderEmail = senderEmail.toLowerCase();
    }
    admin.onboardingCompleted = true;

    // Re-key the admin's own PII from the legacy master key to the tenant DEK:
    // decrypt the current value (getEmail/getPhone), reassign it so the pre('save')
    // hook sees it as modified, then let the hook re-encrypt with the DEK.
    const currentEmail = admin.getEmail();
    if (currentEmail) admin.email = currentEmail;
    const currentPhone = admin.getPhone();
    if (currentPhone) admin.phone = currentPhone;

    // Register the passkey in the in-memory session and warm the DEK cache
    // BEFORE save, so Admin's pre('save') encrypts with this tenant DEK.
    setTenantPasskey(adminId, passkey);
    getTenantDEK(adminId, admin.wrappedDataKey);

    await admin.save();

    // Raw DEK + passkey exist only as locals in this scope and are GC'd on
    // return; DB holds only the two wrapped copies.

    await AuditLog.create({
      actorId: adminId,
      actorRole: 'admin',
      action: 'tenant.onboard',
      actionCategory: 'other',
      targetType: 'admin',
      targetId: adminId,
      tenantAdminId: adminId,
      ipAddress: req.ip || undefined,
      metadata: { senderEmail: senderEmail || '', wrapMethod: 'passkey+vault' }
    });

    return res.status(201).json({
      success: true,
      message: 'Tenant encryption configured. Keep your passkey safe — it cannot be recovered except via the recovery flow.'
    });
  } catch (error) {
    return next(error);
  }
}