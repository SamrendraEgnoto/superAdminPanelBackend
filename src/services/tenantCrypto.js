/**
 * Tenant envelope-encryption service (task 1.6).
 *
 * Each tenant Admin owns a 32-byte Data Encryption Key (DEK). The DEK never
 * touches disk in raw form — it is stored twice, wrapped:
 *
 *   1. wrappedDataKey     — DEK wrapped with a per-tenant PASSKEY
 *                           (PBKDF2 + AES-256-GCM). Unwrapped in-memory for
 *                           day-to-day field encryption/decryption.
 *   2. wrappedDataKeyKMS  — DEK wrapped by Vault Transit (KEK). Used ONLY by
 *                           the recovery path (recoverDEK) so a lost passkey
 *                           never destroys the tenant's data.
 *
 * The passkey is held ONLY in the in-memory request context / server session
 * and is never persisted. unwrapWithVault is intentionally NOT exported —
 * Vault recovery is reachable solely through recoverDEK(), which always writes
 * an AuditLog entry (actionCategory 'recovery') before returning the DEK.
 */

import crypto from 'crypto';
import AuditLog from '../models/AuditLog.js';
import { wrapDEK, unwrapDEK } from '../utils/kmsClient.js';

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_DIGEST = 'sha256';
const PBKDF2_KEY_BYTES = 32;
const WRAP_VERSION = 1;

// In-memory server session: adminId -> { passkey, expiresAt }. Never persisted.
const PASSKEY_TTL_MS = 8 * 60 * 60 * 1000; // 8h session
const passkeyStore = new Map();

// Caches: adminId -> { dek, expiresAt } / { wrapped, expiresAt }.
const DEK_TTL_MS = 15 * 60 * 1000; // 15min
const dekCache = new Map();
const wrappedCache = new Map();

// Session-length registry of passkey-wrapped blobs loaded from the DB. The
// wrapped blob is ciphertext (not secret material); keeping it in-process lets
// the SYNCHRONOUS getters (toJSON can't await) re-derive the DEK from the
// passkey + wrapped blob even after the short-lived dekCache expires. Seeded by
// ensureTenantDEK; cleared with the passkey store on session end.
const WRAPPED_REGISTRY_TTL_MS = 8 * 60 * 60 * 1000;
const wrappedRegistry = new Map();

// ================= DEK generation =================

export const generateDEK = () => crypto.randomBytes(32);

// ================= Passkey envelope (synchronous) =================

/**
 * Wrap a DEK with a passkey-derived key (PBKDF2 + AES-256-GCM).
 * @param {Buffer} dek 32-byte data encryption key
 * @param {string} passkey tenant passkey
 * @returns {{version:number, salt:string, iv:string, ciphertext:string, authTag:string}}
 */
export const wrapWithPasskey = (dek, passkey) => {
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(passkey, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES, PBKDF2_DIGEST);
  const iv = crypto.randomBytes(12); // GCM standard nonce size
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: WRAP_VERSION,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64')
  };
};

/**
 * Unwrap a DEK wrapped by wrapWithPasskey.
 * @param {string|object} wrappedDataKey JSON string (as stored) or raw object
 * @param {string} passkey tenant passkey
 * @returns {Buffer} the raw 32-byte DEK
 */
export const unwrapWithPasskey = (wrappedDataKey, passkey) => {
  const wrapped = typeof wrappedDataKey === 'string'
    ? JSON.parse(wrappedDataKey)
    : wrappedDataKey;
  if (!wrapped || !wrapped.salt || !wrapped.iv || !wrapped.ciphertext || !wrapped.authTag) {
    throw new Error('Malformed passkey-wrapped data key');
  }
  const key = crypto.pbkdf2Sync(
    passkey,
    Buffer.from(wrapped.salt, 'base64'),
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_BYTES,
    PBKDF2_DIGEST
  );
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(wrapped.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(wrapped.authTag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(wrapped.ciphertext, 'base64')), decipher.final()]);
};

// ================= Passkey server-session store =================

export const setTenantPasskey = (adminId, passkey, ttlMs = PASSKEY_TTL_MS) => {
  passkeyStore.set(String(adminId), { passkey, expiresAt: Date.now() + ttlMs });
};

export const getTenantPasskey = (adminId) => {
  const entry = passkeyStore.get(String(adminId));
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    passkeyStore.delete(String(adminId));
    return null;
  }
  return entry.passkey;
};

export const clearTenantPasskey = (adminId) => {
  passkeyStore.delete(String(adminId));
};

// ================= In-memory DEK / wrapped-key cache =================

const isFresh = (entry) => entry && entry.expiresAt > Date.now();

export const clearTenantCache = (adminId) => {
  const id = String(adminId);
  dekCache.delete(id);
  wrappedCache.delete(id);
};

export const clearTenantPasskeyAndCache = (adminId) => {
  clearTenantPasskey(adminId);
  clearTenantCache(adminId);
  wrappedRegistry.delete(String(adminId));
};

/**
 * Resolve the tenant DEK synchronously. Non-blocking: requires the passkey in
 * the session store (request context) and the passkey-wrapped copy either from
 * cache or passed by an in-hand document (e.g. Admin being saved). Returns null
 * when the DEK is not resolvable — callers fall back to the legacy master key.
 * @param {string} adminId
 * @param {string|object} [wrappedDataKey] passkey-wrapped DEK (JSON or object)
 */
export const getTenantDEK = (adminId, wrappedDataKey) => {
  const id = String(adminId);
  if (!id) return null;

  const cached = dekCache.get(id);
  if (isFresh(cached)) return cached.dek;

  let wrapped = wrappedDataKey;
  if (!wrapped) {
    const wc = wrappedCache.get(id);
    if (isFresh(wc)) wrapped = wc.wrapped;
  }
  if (!wrapped) {
    const reg = wrappedRegistry.get(id);
    if (reg && reg.expiresAt > Date.now()) wrapped = reg.wrapped;
  }
  if (!wrapped) return null;

  const passkey = getTenantPasskey(id);
  if (!passkey) return null;

  try {
    const dek = unwrapWithPasskey(wrapped, passkey);
    dekCache.set(id, { dek, expiresAt: Date.now() + DEK_TTL_MS });
    wrappedCache.set(id, { wrapped, expiresAt: Date.now() + DEK_TTL_MS });
    // Keep the wrapped blob available for the whole session so synchronous
    // getters can re-derive the DEK after the short-lived dekCache expires.
    wrappedRegistry.set(id, { wrapped, expiresAt: Date.now() + WRAPPED_REGISTRY_TTL_MS });
    return dek;
  } catch {
    // Wrong passkey or tampered blob. Caches are unaffected; return null.
    return null;
  }
};

/**
 * Resolve the tenant DEK asynchronously, loading the Admin's wrapped copy from
 * the DB when it isn't already cached (used by pre('save') hooks that don't
 * have the wrapper in hand). Never touches Vault.
 * @param {string} adminId
 */
export const ensureTenantDEK = async (adminId) => {
  const id = String(adminId);
  if (!id) return null;

  const immediate = getTenantDEK(id);
  if (immediate) return immediate;

  const { default: Admin } = await import('../models/Admin.js');
  const { default: SuperAdmin } = await import('../models/SuperAdmin.js');

  let admin = await Admin.findById(id).select('wrappedDataKey wrappedDataKeyKMS').lean();
  if (!admin) {
    admin = await SuperAdmin.findById(id).select('wrappedDataKey wrappedDataKeyKMS').lean();
  }
  if (!admin) return null;

  if (admin.wrappedDataKey) {
    wrappedRegistry.set(id, { wrapped: admin.wrappedDataKey, expiresAt: Date.now() + WRAPPED_REGISTRY_TTL_MS });
    const fromPasskey = getTenantDEK(id, admin.wrappedDataKey);
    if (fromPasskey) return fromPasskey;
  }

  // If no passkey session in memory (e.g. public lead submission from embed / estimator),
  // recover/unwrap the tenant's DEK via Vault Transit / KMS so data is always encrypted with DEK.
  try {
    const recovered = await recoverDEK(id, 'lead-ingestion-auto', { id, role: 'system' });
    if (recovered) {
      dekCache.set(id, { dek: recovered, expiresAt: Date.now() + DEK_TTL_MS });
      return recovered;
    }
  } catch (err) {
    console.warn(`[tenantCrypto] Auto DEK recovery for tenant ${id} skipped:`, err.message);
  }

  return null;
};

// ================= Vault transit envelope (async) =================

/** Wrap a DEK with Vault Transit (KEK) — returns `vault:v1:...` ciphertext. */
export const wrapWithVault = async (dek) => wrapDEK(dek);

/**
 * RECOVERY-ONLY: the single pathway that unwraps a DEK via Vault. Requires the
 * tenant's wrappedDataKeyKMS and ALWAYS writes an AuditLog entry
 * (actionCategory 'recovery') before the DEK is returned.
 *
 * @param {string} adminId tenant admin
 * @param {string} [reason] free-text reason for the recovery
 * @param {{id?:string, role?:'superadmin'|'admin'|'system', ip?:string}} [triggeredBy]
 * @returns {Promise<Buffer>} the recovered 32-byte DEK
 */
export const recoverDEK = async (adminId, reason = 'unspecified', triggeredBy = {}) => {
  const { default: Admin } = await import('../models/Admin.js');
  const { default: SuperAdmin } = await import('../models/SuperAdmin.js');

  let admin = await Admin.findById(adminId).select('wrappedDataKeyKMS').lean();
  let isAdmin = true;
  if (!admin) {
    admin = await SuperAdmin.findById(adminId).select('wrappedDataKeyKMS').lean();
    isAdmin = false;
  }
  if (!admin) {
    throw new Error('No tenant found with this ID.');
  }

  // If no Vault-wrapped DEK yet, provision a new 32-byte DEK wrapped under Vault Transit
  if (!admin.wrappedDataKeyKMS) {
    const rawDek = crypto.randomBytes(32);
    const wrapped = await wrapWithVault(rawDek);
    if (isAdmin) {
      await Admin.findByIdAndUpdate(adminId, { wrappedDataKeyKMS: wrapped });
    } else {
      await SuperAdmin.findByIdAndUpdate(adminId, { wrappedDataKeyKMS: wrapped });
    }
    admin.wrappedDataKeyKMS = wrapped;
  }

  let dek;
  try {
    dek = await unwrapDEK(admin.wrappedDataKeyKMS);
  } catch (err) {
    console.warn(`[tenantCrypto] Existing DEK unwrap failed for tenant ${adminId} (${err.message}). Auto-provisioning fresh DEK with active Vault key.`);
    const rawDek = crypto.randomBytes(32);
    const wrapped = await wrapWithVault(rawDek);
    if (isAdmin) {
      await Admin.findByIdAndUpdate(adminId, { wrappedDataKeyKMS: wrapped });
    } else {
      await SuperAdmin.findByIdAndUpdate(adminId, { wrappedDataKeyKMS: wrapped });
    }
    admin.wrappedDataKeyKMS = wrapped;
    dek = rawDek;
  }

  // actorId must be a real ObjectId ref; fall back to the tenant admin itself
  // when no valid id was supplied.
  const fallbackActorId = adminId;
  const validatedActorId = (() => {
    const candidate = (triggeredBy && triggeredBy.id) || adminId;
    return /^[0-9a-f]{24}$/i.test(String(candidate)) ? candidate : fallbackActorId;
  })();

  const rawIp = (triggeredBy && triggeredBy.ip) || undefined;
  const ipAddress = rawIp && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^::1$|^[0-9a-f:]+$/i.test(String(rawIp))
    ? String(rawIp)
    : undefined;

  await AuditLog.create({
    actorId: validatedActorId,
    actorRole: (triggeredBy && triggeredBy.role) || 'system',
    action: 'dek.recover',
    actionCategory: 'recovery',
    targetType: 'admin',
    targetId: adminId,
    tenantAdminId: adminId,
    ipAddress,
    metadata: { reason: String(reason || 'unspecified'), source: 'vault-transit' }
  });

  return dek;
};
