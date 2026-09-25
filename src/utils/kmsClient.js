/**
 * HashiCorp Vault KMS client — Transit engine (DEK wrapping layer).
 *
 * KMS_MODE env var controls the active backend:
 *   'vault'  (production) — Real HashiCorp Vault Transit, AppRole auth.
 *                           Set VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID.
 *   'local'  (dev/test)   — AES-256-CBC wrap using ENCRYPTION_MASTER_KEY.
 *                           No Vault process needed; no network call.
 *
 * When KMS_MODE=local the Vault AppRole login is never attempted, so the
 * ECONNREFUSED error on startup disappears completely.
 *
 * wrapDEK(rawDEKBuffer)       -> wrapped ciphertext (format depends on mode)
 * unwrapDEK(wrappedCiphertext) -> raw DEK Buffer
 *
 * Field-level AES-256-CBC encryption (encryption.js) is intentionally NOT
 * touched here — this is the KEK/DEK wrapping layer only (task 1.5).
 */

import crypto from 'crypto';
import https from 'https';
import axios from 'axios';
import { encryptField, decryptField } from './encryption.js';

// Default transit key name (can be overridden via VAULT_TRANSIT_KEY)
const DEFAULT_TRANSIT_KEY = 'tenant-master-key';

// ---- KMS mode selection ----
// Set KMS_MODE=local in .env for local development (no Vault needed).
// Set KMS_MODE=vault in production with a live Vault instance.
const isLocalMode = () => (process.env.KMS_MODE || 'local').toLowerCase() === 'local';

const REQUEST_TIMEOUT_MS = 10000;
// Refresh the token slightly before it actually expires so in-flight ops never
// race the lease boundary.
const TOKEN_REFRESH_SLACK_S = 60;

// Read Vault connection config lazily (per call) so import order never matters —
// whether dotenv, PM2 env, or a test sets process.env first.
const vaultConfig = () => {
  const addr = (process.env.VAULT_ADDR || 'http://127.0.0.1:8200').replace(/\/+$/, '');
  const transitKey = process.env.VAULT_TRANSIT_KEY || DEFAULT_TRANSIT_KEY;
  const isHttps = addr.startsWith('https://');
  const skipVerify = process.env.VAULT_SKIP_VERIFY === 'true' ||
    process.env.VAULT_SKIP_VERIFY === '1' ||
    addr.includes('127.0.0.1') ||
    addr.includes('localhost');

  return {
    addr,
    roleId: process.env.VAULT_ROLE_ID || '',
    secretId: process.env.VAULT_SECRET_ID || '',
    token: process.env.VAULT_TOKEN || '',
    transitKey,
    httpsAgent: isHttps && skipVerify ? new https.Agent({ rejectUnauthorized: false }) : undefined
  };
};

// ---- AppRole session state ----
let tokenInfo = { token: null, expiresAt: 0 };
// In-flight login promise so concurrent first calls share one login.
let loginPromise = null;

const isTokenValid = () => {
  // If a static VAULT_TOKEN is set in env, it is always considered valid
  const cfg = vaultConfig();
  if (cfg.token) return true;
  return !!tokenInfo.token && Date.now() < tokenInfo.expiresAt;
};

const appRoleLogin = async () => {
  const { addr, roleId, secretId, token: staticToken, httpsAgent } = vaultConfig();
  if (staticToken) {
    tokenInfo.token = staticToken;
    tokenInfo.expiresAt = Date.now() + 365 * 24 * 3600 * 1000;
    loginPromise = null;
    return staticToken;
  }

  if (!roleId || !secretId) {
    throw new Error(
      'Vault credentials missing. Set VAULT_TOKEN or (VAULT_ROLE_ID and VAULT_SECRET_ID). ' +
      '(VAULT_ADDR defaults to http://127.0.0.1:8200).'
    );
  }
  const { data } = await axios.post(
    `${addr}/v1/auth/approle/login`,
    { role_id: roleId, secret_id: secretId },
    { timeout: REQUEST_TIMEOUT_MS, httpsAgent }
  );
  const auth = data && data.auth;
  if (!auth || !auth.client_token) {
    throw new Error('Vault AppRole login failed: no client_token returned');
  }
  const leaseSeconds = Number.isFinite(auth.lease_duration) && auth.lease_duration > 0
    ? auth.lease_duration
    : 3600;
  tokenInfo.token = auth.client_token;
  tokenInfo.expiresAt = Date.now() + Math.max(60, (leaseSeconds - TOKEN_REFRESH_SLACK_S)) * 1000;
  loginPromise = null;
  return tokenInfo.token;
};

const ensureToken = async () => {
  const cfg = vaultConfig();
  if (cfg.token) return cfg.token;
  if (isTokenValid()) return tokenInfo.token;
  if (!loginPromise) {
    loginPromise = appRoleLogin();
    loginPromise.catch(() => { loginPromise = null; });
  }
  await loginPromise;
  if (!isTokenValid()) {
    // Belt and suspenders: if the resolved token still fails validation, retry once.
    loginPromise = null;
    return ensureToken();
  }
  return tokenInfo.token;
};

const vaultRequest = async (method, path, body) => {
  const { addr, httpsAgent } = vaultConfig();
  const perform = async (token) => {
    const { data } = await axios({
      method,
      url: `${addr}/v1/${path}`,
      data: body,
      headers: {
        'X-Vault-Token': token,
        'Content-Type': 'application/json'
      },
      timeout: REQUEST_TIMEOUT_MS,
      httpsAgent
    });
    return data;
  };

  try {
    return await perform(await ensureToken());
  } catch (err) {
    if (err.response && err.response.data) {
      console.error(`[KMS] Vault request (${method} ${path}) failed (${err.response.status}):`, JSON.stringify(err.response.data));
    }
    // Token invalid/expired at the server -> force a fresh login and retry once (unless using static token).
    const cfg = vaultConfig();
    if (!cfg.token && err.response && err.response.status === 403) {
      tokenInfo.token = null;
      tokenInfo.expiresAt = 0;
      loginPromise = null;
      return perform(await ensureToken());
    }
    throw err;
  }
};

// ---- Local-mode DEK wrap/unwrap using ENCRYPTION_MASTER_KEY ----
// Format: 'local:<iv_hex>:<ciphertext_hex>' so it's easily distinguishable
// from real Vault ciphertext (which starts with 'vault:v1:').

const localWrapDEK = (rawDEKBuffer) => {
  const masterKey = process.env.ENCRYPTION_MASTER_KEY;
  if (!masterKey) throw new Error('ENCRYPTION_MASTER_KEY is not set in .env (required for KMS_MODE=local)');
  const key = Buffer.from(masterKey, 'hex').slice(0, 32); // AES-256 needs 32 bytes
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const buf = Buffer.isBuffer(rawDEKBuffer) ? rawDEKBuffer : Buffer.from(rawDEKBuffer);
  const encrypted = Buffer.concat([cipher.update(buf), cipher.final()]);
  return `local:${iv.toString('hex')}:${encrypted.toString('hex')}`;
};

const localUnwrapDEK = (wrappedCiphertext) => {
  if (!wrappedCiphertext || !wrappedCiphertext.startsWith('local:')) {
    throw new Error(`localUnwrapDEK: unexpected format '${wrappedCiphertext}'`);
  }
  const masterKey = process.env.ENCRYPTION_MASTER_KEY;
  if (!masterKey) throw new Error('ENCRYPTION_MASTER_KEY is not set in .env (required for KMS_MODE=local)');
  const key = Buffer.from(masterKey, 'hex').slice(0, 32);
  const parts = wrappedCiphertext.split(':');
  const iv = Buffer.from(parts[1], 'hex');
  const ciphertext = Buffer.from(parts[2], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
};

/**
 * Wrap a raw data-encryption-key.
 * In vault mode: Vault Transit encrypt → returns `vault:v1:<base64>`
 * In local mode: AES-256-CBC with ENCRYPTION_MASTER_KEY → returns `local:<iv>:<ct>`
 * @param {Buffer|Uint8Array|string} rawDEKBuffer
 * @returns {Promise<string>}
 */
export const wrapDEK = async (rawDEKBuffer) => {
  if (isLocalMode()) return localWrapDEK(rawDEKBuffer);
  try {
    const buf = Buffer.isBuffer(rawDEKBuffer)
      ? rawDEKBuffer
      : Buffer.from(rawDEKBuffer);
    const { transitKey } = vaultConfig();
    const { data } = await vaultRequest(
      'post',
      `transit/encrypt/${transitKey}`,
      { plaintext: buf.toString('base64') }
    );
    const ciphertext = (data && data.data && data.data.ciphertext) || (data && data.ciphertext);
    if (!ciphertext || typeof ciphertext !== 'string' || !ciphertext.startsWith('vault:v1:')) {
      throw new Error(`Vault Transit encrypt returned unexpected ciphertext format: ${JSON.stringify(data)}`);
    }
    return ciphertext;
  } catch (vaultErr) {
    console.warn(`[KMS] Vault Transit encrypt unavailable (${vaultErr.message}). Failing over to local KEK.`);
    return localWrapDEK(rawDEKBuffer);
  }
};

/**
 * Unwrap a wrapped data-encryption-key.
 * Detects mode from the ciphertext prefix:
 *   'vault:v1:...' → Vault Transit decrypt
 *   'local:...'    → local AES-256-CBC decrypt
 * This ensures backward-compatibility if mode changes between runs.
 * @param {string} wrappedCiphertext
 * @returns {Promise<Buffer>}
 */
export const unwrapDEK = async (wrappedCiphertext) => {
  // Auto-detect format so existing local: or vault: keys keep working
  // regardless of current KMS_MODE setting.
  if (typeof wrappedCiphertext === 'string' && wrappedCiphertext.startsWith('local:')) {
    return localUnwrapDEK(wrappedCiphertext);
  }
  if (typeof wrappedCiphertext === 'string' && wrappedCiphertext.startsWith('vault:v1:')) {
    try {
      const { transitKey } = vaultConfig();
      const { data } = await vaultRequest(
        'post',
        `transit/decrypt/${transitKey}`,
        { ciphertext: wrappedCiphertext }
      );
      const plaintext = (data && data.data && data.data.plaintext) || (data && data.plaintext);
      if (!plaintext) throw new Error(`Vault Transit decrypt returned no plaintext: ${JSON.stringify(data)}`);
      return Buffer.from(plaintext, 'base64');
    } catch (vaultErr) {
      console.warn(`[KMS] Vault Transit decrypt unavailable (${vaultErr.message}).`);
      throw vaultErr;
    }
  }
  // Fallback: if neither prefix is found, treat as legacy base64-wrapped key
  return Buffer.from(wrappedCiphertext, 'base64');
};

/**
 * Authenticate against Vault at startup (fire-and-forget). Does not block app
 * boot if Vault is temporarily unavailable — operations that need the token
 * will trigger (and await) a fresh login themselves.
 */
export const initializeVault = () => {
  if (isLocalMode()) {
    console.log('[KMS] Running in LOCAL mode (KMS_MODE=local). Vault is not used.');
    console.log('[KMS] Set KMS_MODE=vault with valid VAULT_* env vars for production.');
    return Promise.resolve();
  }
  const { addr, transitKey, token } = vaultConfig();
  console.log(`[KMS] Running in VAULT mode (KMS_MODE=vault).`);
  console.log(`[KMS] Vault Addr: ${addr} | Transit Key: ${transitKey} | Auth: ${token ? 'static-token' : 'approle'}`);
  return ensureToken().then(() => {
    console.log('[KMS] Successfully authenticated with HashiCorp Vault!');
  }).catch((err) => {
    const errorDetails = err.response?.data?.errors ? err.response.data.errors.join(', ') : err.message;
    console.error('[KMS] Vault authentication failed at startup:', errorDetails);
    console.error('[KMS] If you are in dev, set KMS_MODE=local in your .env to skip Vault.');
  });
};

// ================= Backward-compatible data-key helpers =================

/**
 * Generate a fresh 32-byte data key and wrap it via Vault Transit.
 * @returns {Promise<{dataKey: Buffer, wrappedDataKey: string}>}
 */
export const wrapDataKey = async () => {
  const dataKey = crypto.randomBytes(32);
  const wrappedDataKey = await wrapDEK(dataKey);
  return { dataKey, wrappedDataKey };
};

/**
 * Unwrap a Vault Transit-wrapped data key.
 * @param {string} wrappedDataKey - Vault ciphertext (`vault:v1:...`)
 * @returns {Promise<Buffer>} the plaintext data key
 */
export const unwrapDataKey = async (wrappedDataKey) => unwrapDEK(wrappedDataKey);

/**
 * Resolve the plaintext data key for an Admin. Kept for compatibility; callers
 * that only need field-level encryption should use encryptField/decryptField
 * directly (the DEK/KMS layer is separate from field logic per task 1.5/1.6).
 */
export const getDataKey = async () => {
  const { dataKey } = await wrapDataKey();
  return dataKey;
};

/**
 * Field-level encryption remains the encryption.js AES-256-CBC path; these
 * wrappers are kept so Admin.js (and any other caller) keeps its import working
 * while the wrapping layer is moved to Vault Transit.
 */
export const encryptFieldWithKMS = async (plaintext) => encryptField(plaintext);
export const decryptFieldWithKMS = async (encryptedBase64) => decryptField(encryptedBase64);

export const KMS_CONFIG = {
  get addr() { return vaultConfig().addr; },
  get keyId() { return vaultConfig().transitKey; },
  get auth() { return vaultConfig().token ? 'token' : 'approle'; }
};

export { DEFAULT_TRANSIT_KEY as VAULT_TRANSIT_KEY };
