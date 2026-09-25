import crypto from 'crypto';

const AUTHORIZED_AAD = 'egnoto-3d-estimator:v1';
const getBlindIndexSalt = () => process.env.BLIND_INDEX_SECRET || process.env.ENCRYPTION_MASTER_KEY || 'egnoto-blind-index-salt-v1';

// Derive a 32-byte key from the master key using SHA-256
const deriveKey = () => {
  if (!process.env.ENCRYPTION_MASTER_KEY) {
    console.warn('ENCRYPTION_MASTER_KEY not set. Using fallback deterministic key.');
    return crypto.createHash('sha256').update('egnoto-default-master-key-seed').digest();
  }
  return crypto.createHash('sha256').update(process.env.ENCRYPTION_MASTER_KEY).digest();
};

const effectiveKey = (key) => {
  if (Buffer.isBuffer(key) && key.length === 32) return key;
  if (typeof key === 'string' && key.length === 64) return Buffer.from(key, 'hex');
  return deriveKey();
};

/**
 * Encrypt a plaintext string using AES-256-GCM.
 * Compatible with 3D Estimator and Super Admin Panel.
 * Returns compact string: `gcm:<iv_base64>:<tag_base64>:<ct_base64>`
 *
 * @param {string} plaintext
 * @param {Buffer} [key] 32-byte DEK Buffer
 * @param {string} [aad] Optional AAD
 * @returns {string|null}
 */
const encryptField = (plaintext, key, aad = AUTHORIZED_AAD) => {
  if (!plaintext || typeof plaintext !== 'string' || plaintext.length === 0) {
    return null;
  }

  try {
    const keyBuf = effectiveKey(key);
    const iv = crypto.randomBytes(12); // Standard 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
    if (aad) {
      cipher.setAAD(Buffer.from(aad, 'utf8'));
    }

    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return `gcm:${iv.toString('base64')}:${tag.toString('base64')}:${ct.toString('base64')}`;
  } catch (error) {
    console.error('Encryption error (AES-256-GCM):', error.message);
    return null;
  }
};

/**
 * Decrypt a field encrypted with either:
 *  1. AES-256-GCM object: { iv, tag, ct }
 *  2. AES-256-GCM JSON string: '{"iv":"...","tag":"...","ct":"..."}'
 *  3. AES-256-GCM compact string: 'gcm:<iv>:<tag>:<ct>'
 *  4. Legacy AES-256-CBC base64 string: <16-byte IV><ciphertext>
 *  5. Plaintext string fallback
 *
 * @param {string|object} ciphertext
 * @param {Buffer} [key] 32-byte DEK Buffer
 * @param {string} [aad] Optional AAD
 * @returns {string|null}
 */
const decryptField = (ciphertext, key, aad = AUTHORIZED_AAD) => {
  if (!ciphertext) return null;

  const keyBuf = effectiveKey(key);

  // 1. Handle object payload { iv, tag, ct }
  if (typeof ciphertext === 'object' && ciphertext.iv && ciphertext.tag && ciphertext.ct) {
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        keyBuf,
        Buffer.from(ciphertext.iv, 'base64')
      );
      if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
      decipher.setAuthTag(Buffer.from(ciphertext.tag, 'base64'));
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext.ct, 'base64')),
        decipher.final()
      ]).toString('utf8');
    } catch {
      // If AAD differed or key differed, try without AAD
      try {
        const decipher2 = crypto.createDecipheriv(
          'aes-256-gcm',
          keyBuf,
          Buffer.from(ciphertext.iv, 'base64')
        );
        decipher2.setAuthTag(Buffer.from(ciphertext.tag, 'base64'));
        return Buffer.concat([
          decipher2.update(Buffer.from(ciphertext.ct, 'base64')),
          decipher2.final()
        ]).toString('utf8');
      } catch {
        return null;
      }
    }
  }

  if (typeof ciphertext !== 'string') return null;
  const trimmed = ciphertext.trim();

  // 2. Handle JSON-encoded GCM string
  if (trimmed.startsWith('{') && trimmed.includes('"iv"') && trimmed.includes('"ct"')) {
    try {
      const parsed = JSON.parse(trimmed);
      return decryptField(parsed, key, aad);
    } catch {}
  }

  // 3. Handle compact GCM format: `gcm:<iv>:<tag>:<ct>`
  if (trimmed.startsWith('gcm:')) {
    const parts = trimmed.split(':');
    if (parts.length === 4) {
      return decryptField({ iv: parts[1], tag: parts[2], ct: parts[3] }, key, aad);
    }
  }

  // 4. Handle legacy AES-256-CBC: base64(<16-byte IV><ciphertext>)
  try {
    const buf = Buffer.from(trimmed, 'base64');
    if (buf.length > 16) {
      const iv = buf.slice(0, 16);
      const ct = buf.slice(16);
      const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, iv);
      const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
      if (decrypted && /^[\x20-\x7E\s]+$/.test(decrypted)) {
        return decrypted;
      }
    }
  } catch {}

  // 5. If it looks like plain readable text (e.g. contains @ for email or is short text), return as-is
  if (trimmed.includes('@') || (trimmed.length < 40 && !/^[A-Za-z0-9+/=]{44,}$/.test(trimmed))) {
    return trimmed;
  }

  return null;
};

/**
 * Hash an email or identifier for blind-indexed lookup (HMAC-SHA256).
 * Salted to protect against rainbow-table attacks (GDPR / DPDP / SOC 2 compliance).
 *
 * @param {string} email
 * @returns {string|null}
 */
const hashEmail = (email) => {
  if (!email || typeof email !== 'string') return null;
  const normalized = email.toLowerCase().trim();
  // Salted HMAC-SHA256
  return crypto.createHmac('sha256', getBlindIndexSalt()).update(normalized).digest('hex');
};

/**
 * Legacy un-salted SHA256 email hash for backward-compatible lookup of older records
 */
const legacyHashEmail = (email) => {
  if (!email || typeof email !== 'string') return null;
  return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
};

export {
  encryptField,
  decryptField,
  hashEmail,
  legacyHashEmail,
  AUTHORIZED_AAD
};
