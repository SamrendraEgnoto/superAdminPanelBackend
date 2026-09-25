/**
 * HTTPS Enforcement Middleware for Bridge Routes
 * Ensures bridge traffic only occurs over HTTPS.
 * In production, this should be enforced at the proxy/load balancer level.
 * This middleware provides application-level enforcement and logging.
 */
const enforceHTTPS = (req, res, next) => {
  // In production (not development), enforce HTTPS
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (isProduction && !req.secure) {
    // Log the violation
    console.warn('[HTTPS] Non-HTTPS request detected on bridge endpoint. Request rejected.');
    return res.status(503).json({ 
      message: 'Service Unavailable: Bridge endpoints require HTTPS' 
    });
  }
  
  // Log HTTP requests in production for monitoring
  if (isProduction && !req.secure) {
    console.log('[HTTPS] Non-HTTPS bridge access attempt: {req.method} {req.originalUrl}');
  }
  
  next();
};

export default enforceHTTPS;