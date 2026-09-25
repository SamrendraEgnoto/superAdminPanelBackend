
export function allowRoles(roles = []) {
  if (!Array.isArray(roles)) {
    roles = [roles];
  }

  const normalizedRoles = roles.map(r => r.toLowerCase());

  return (req, res, next) => {
    const userRole = req.user?.role?.toLowerCase();
    const effectiveRoles = [...normalizedRoles];
    if (effectiveRoles.includes('superadmin') && !effectiveRoles.includes('root')) {
      effectiveRoles.push('root');
    }
    if (!req.user || !effectiveRoles.includes(userRole)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

// Restricts a route to the root Super Admin only. Delegated Super Admins must
// never be able to create or manage other Super Admins (per hierarchy design).
export function requireRoot(req, res, next) {
  if (!req.user || (req.user.dbRole !== 'root' && req.user.role !== 'root')) {
    return res.status(403).json({ message: 'Forbidden: root Super Admin access required' });
  }
  next();
}