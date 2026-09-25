/**
 * Internal service-to-service authentication middleware.
 *
 * Guards the /api/internal router. Callers (e.g. the 3D Estimator) must send
 * the shared secret in the `X-Internal-Secret` header. This is intentionally
 * separate from embedKeyAuth (1.4, browser-facing embed keys) and from user JWT
 * auth — it exists ONLY for trusted service calls and must never be exposed to
 * a browser or end user. In production /api/internal/* is further restricted to
 * localhost / the internal network at the firewall or reverse-proxy level.
 */
const internalAuth = (req, res, next) => {
  const expected = process.env.INTERNAL_SERVICE_SECRET;
  const provided = req.headers && req.headers['x-internal-secret'];

  if (!expected || !provided || provided !== expected) {
    console.warn(`[Internal Auth] Rejected call to ${req.method} ${req.originalUrl || req.url} (missing or mismatched X-Internal-Secret)`);
    return res.status(403).json({ success: false, message: 'Forbidden: invalid or missing internal service secret' });
  }

  next();
};

export default internalAuth;