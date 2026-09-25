import { verifyCustomerToken } from '../utils/customerToken.js';

/**
 * Customer Rights token auth (no admin JWT, no session).
 *
 * Accepts the token via the `?token=` query parameter (used by emailed links)
 * or an `Authorization: Bearer <token>` header. Rejects:
 *   - 401 when the token is missing, expired, or malformed
 *   - 403 when the token is valid but scoped to a DIFFERENT lead
 */
export function requireCustomerToken(req, res, next) {
  const fromHeader = req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
    ? req.headers.authorization.slice(7)
    : null;
  const token = req.query.token || fromHeader;

  if (!token) {
    return res.status(401).json({ message: 'Customer token required' });
  }

  const payload = verifyCustomerToken(token);
  if (!payload) {
    return res.status(401).json({ message: 'Invalid or expired customer token' });
  }

  if (String(payload.leadId) !== String(req.params.leadId)) {
    return res.status(403).json({ message: 'Token is not valid for this lead' });
  }

  req.customer = { leadId: String(payload.leadId) };
  next();
}