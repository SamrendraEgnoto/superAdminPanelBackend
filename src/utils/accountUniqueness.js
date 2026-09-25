import SuperAdmin from '../models/SuperAdmin.js';
import Admin from '../models/Admin.js';
import User from '../models/User.js';
import { hashEmail, legacyHashEmail } from './encryption.js';

/**
 * Checks if an email is already used anywhere across the platform:
 * - SuperAdmin (Root & Delegated)
 * - Admin (Tenant & Data-Viewer)
 * - User (Team members, Employees, etc.)
 *
 * Uses deterministic salted HMAC-SHA256 blind indexing (hashEmail) so it can
 * match across encrypted fields without decrypting the entire database.
 *
 * @param {string} email - Plaintext email to check
 * @param {string|mongoose.Types.ObjectId} [excludeId] - Optional doc ID to exclude (for update operations)
 * @returns {Promise<{exists: boolean, role?: string, message?: string}>}
 */
export async function checkEmailExistsAcrossAllRoles(email, excludeId = null) {
  if (!email || typeof email !== 'string') return { exists: false };
  const normalized = email.toLowerCase().trim();
  const hash = hashEmail(normalized);
  const legacyHash = legacyHashEmail(normalized);

  const hashes = [hash, legacyHash].filter(Boolean);

  const excludeFilter = excludeId ? { _id: { $ne: excludeId } } : {};

  // 1. Check SuperAdmin
  const sa = await SuperAdmin.findOne({
    ...excludeFilter,
    $or: [
      { email: normalized },
      { emailHash: { $in: hashes } }
    ]
  }).select('_id role email').lean();

  if (sa) {
    const roleName = sa.role === 'root' ? 'Root Super Admin' : 'Delegated Super Admin';
    return {
      exists: true,
      role: roleName,
      message: `An account with this email already exists (${roleName}). Each email can only be registered once across the platform.`
    };
  }

  // 2. Check Admin
  const admin = await Admin.findOne({
    ...excludeFilter,
    $or: [
      { email: normalized },
      { emailHash: { $in: hashes } }
    ]
  }).select('_id adminType email').lean();

  if (admin) {
    const roleName = admin.adminType === 'data-viewer' ? 'Data Viewer Admin' : 'Admin';
    return {
      exists: true,
      role: roleName,
      message: `An account with this email already exists (${roleName}). Each email can only be registered once across the platform.`
    };
  }

  // 3. Check User
  const user = await User.findOne({
    ...excludeFilter,
    $or: [
      { email: normalized },
      { emailHash: { $in: hashes } }
    ]
  }).select('_id role email').lean();

  if (user) {
    return {
      exists: true,
      role: 'User',
      message: `An account with this email already exists (User). Each email can only be registered once across the platform.`
    };
  }

  return { exists: false };
}
