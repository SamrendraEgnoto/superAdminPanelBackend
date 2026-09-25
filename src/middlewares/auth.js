
import jwt from 'jsonwebtoken';
import SuperAdmin from '../models/SuperAdmin.js';
import Admin from '../models/Admin.js';
import User from '../models/User.js';

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

export async function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token missing' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const role = payload.role?.toLowerCase();

    let model;
    let normalizedRole = role;

    if (role === 'root') {
      model = SuperAdmin;
      normalizedRole = 'root';
    } else if (role === 'superadmin' || role === 'delegated') {
      model = SuperAdmin;
      normalizedRole = 'superadmin';
    } else if (role === 'admin') {
      model = Admin;
      normalizedRole = 'admin';
    } else {
      model = User;
      if (['manager', 'employee', 'editor', 'standard'].includes(role)) {
        normalizedRole = 'user';
      }
    }

    const user = await model.findById(payload.id).select('-password');
    if (!user) return res.status(401).json({ message: 'User not found' });

    // Ensure non-root users cannot use a root token
    if (normalizedRole === 'root' && user.role !== 'root') {
      return res.status(403).json({ message: 'Forbidden: Invalid root credentials' });
    }

    // SaaS Enhancement: Check if Admin is active
    if (normalizedRole === 'admin') {
      if (!user.isActive) {
        return res.status(403).json({ success: false, message: 'Account is deactivated. Please contact Super Admin.' });
      }
    } else if (normalizedRole === 'user') {
      if (user.isActive === false) {
        return res.status(403).json({ success: false, message: 'Your account is deactivated. Please contact your administrator.' });
      }
      const orgId = user.adminId || user.createdBy;
      if (orgId) {
        const admin = await Admin.findById(orgId);
        if (admin) {
          if (!admin.isActive) {
            return res.status(403).json({ success: false, message: 'Organization account is deactivated. Please contact your Admin.' });
          }
        } else {
          // If not in Admin collection, check SuperAdmin (e.g. created by DSA)
          const sa = await SuperAdmin.findById(orgId);
          if (!sa) {
            return res.status(403).json({ success: false, message: 'Organization account not found. Please contact support.' });
          }
        }
      }
    }

    req.user = {
      id: user._id.toString(),
      role: normalizedRole, 
      // dbRole is the precise role from the document (e.g. SuperAdmin
      // 'root' vs 'delegated'), needed to distinguish root from delegated.
      dbRole: user.role,
      email: user.getEmail ? user.getEmail() : user.email,
      firstName: user.getFirstName ? user.getFirstName() : user.firstName,
      lastName: user.getLastName ? user.getLastName() : user.lastName,
      adminId: user.adminId || user.createdBy || user._id,
      // createdById is how Admin model stores the parent SA/DSA reference;
      // createdBy is the field name used on User model. Expose both under
      // a single consistent key so buildingController never reads undefined.
      createdBy: user.createdById || user.createdBy || null,
      canCreateLead: ['admin', 'superadmin'].includes(normalizedRole) || (user.permissions && user.permissions.canCreateLead) || false
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}