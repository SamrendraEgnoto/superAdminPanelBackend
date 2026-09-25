import jwt from 'jsonwebtoken';

/**
 * Customer Rights Token
 *
 * A short-lived, lead-scoped JWT (NOT an admin auth JWT) that is embedded in
 * the confirmation email link sent to the customer, e.g.:
 *
 *   https://.../api/customer/<leadId>/export?token=<jwt>
 *
 * The token:
 *  - is signed with its own secret (CUSTOMER_TOKEN_SECRET), separate from the
 *    admin/superadmin JWT secret, and
 *  - is scoped to exactly ONE lead via the `leadId` claim — the customer-rights
 *    endpoints require payload.leadId === :leadId.
 */

const CUSTOMER_TOKEN_SECRET = process.env.CUSTOMER_TOKEN_SECRET || 'customer-token-secret-change-me';
const CUSTOMER_TOKEN_TTL = '30d';

// Base URL used to build the customer-rights link embedded in emails. Points at
// the public customer-rights API origin (frontend can proxy/embed as needed).
const CUSTOMER_RIGHTS_BASE_URL = process.env.CUSTOMER_RIGHTS_BASE_URL || 'http://localhost:5001';

/**
 * Sign a lead-scoped customer-rights token.
 * @param {string|ObjectId} leadId the lead the token is scoped to
 * @returns {string} JWT
 */
export const signCustomerToken = (leadId) => {
  return jwt.sign(
    { leadId: String(leadId), scope: 'customer-rights' },
    CUSTOMER_TOKEN_SECRET,
    { expiresIn: CUSTOMER_TOKEN_TTL }
  );
};

/**
 * Verify a customer-rights token.
 * @param {string} token JWT
 * @returns {object|null} decoded payload ({ leadId, scope, iat, exp }) or null
 */
export const verifyCustomerToken = (token) => {
  try {
    return jwt.verify(token, CUSTOMER_TOKEN_SECRET);
  } catch {
    return null;
  }
};

/**
 * Build the token + ready-made link for a lead, for embedding in confirmation
 * emails so the customer can exercise their rights (export / correct / erase).
 * @param {string|ObjectId} leadId
 * @returns {{customerRightsToken: string, customerRightsUrl: string}}
 */
export const buildCustomerRightsLink = (leadId) => {
  const token = signCustomerToken(leadId);
  return {
    customerRightsToken: token,
    customerRightsUrl: `${CUSTOMER_RIGHTS_BASE_URL}/api/customer/${String(leadId)}/export?token=${encodeURIComponent(token)}`
  };
};