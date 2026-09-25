import { setTenantPasskey } from '../services/tenantCrypto.js';

/**
 * Mount AFTER authenticateJWT. If the client supplied an `x-tenant-passkey`
 * header (the tenant admin's passkey, stored ONLY in this in-memory server
 * session), register it so downstream pre('save') hooks can unwrap the
 * tenant's DEK for field-level encryption/decryption during normal operation.
 *
 * For an admin JWT the tenant is the admin themselves; for a team-member user
 * the tenant is req.user.adminId.
 */
export function tenantPasskeyContext(req, res, next) {
  const passkey = req.headers['x-tenant-passkey'];
  if (passkey && req.user && req.user.id) {
    const tenantAdminId = String(req.user.adminId || req.user.id);
    setTenantPasskey(tenantAdminId, passkey);
  }
  next();
}