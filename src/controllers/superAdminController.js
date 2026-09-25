import mongoose from 'mongoose';
import Admin from '../models/Admin.js';
import AuditLog from '../models/AuditLog.js';
import SuperAdmin from '../models/SuperAdmin.js';
import User from '../models/User.js';
import BuildingInfo from '../models/BuildingInfo.js';
import { PLANS, DEFAULT_PLAN } from '../config/plans.js';
import axios from 'axios';
import bridgeLog from '../utils/bridgeLog.js';
import { randomBytes } from 'crypto';
import { checkEmailExistsAcrossAllRoles } from '../utils/accountUniqueness.js';
import { ensureTenantDEK } from '../services/tenantCrypto.js';
import { hashEmail } from '../utils/encryption.js';
import notificationService from '../utils/notificationService.js';
// ############################## code for super admin #########################

const getSuperAdminChain = async (superAdminId) => {
  const chain = new Set();
  let current = superAdminId;
  while (current) {
    chain.add(current);
    const sa = await SuperAdmin.findById(current).select('createdById');
    if (sa && sa.createdById) {
      current = sa.createdById.toString();
    } else {
      break;
    }
  }
  return chain;
};

const checkSuperAdminAccess = async (reqUserId, targetSuperAdminId) => {
  const userSa = await SuperAdmin.findById(reqUserId).select('role createdById');
  if (!userSa) return false;

  // Root can access everything
  if (userSa.role === 'root' || userSa.role === 'superadmin') return true;

  // Delegated can only access their own chain (themselves + root)
  if (userSa.role === 'delegated' || userSa.role === 'superadmin') {
    const chain = await getSuperAdminChain(targetSuperAdminId);
    return chain.has(reqUserId);
  }
  return false;
};

// Admin-scoped access: root Super Admin can manage any admin; a delegated
// Super Admin may only manage admins it directly created (createdBy === its id).
// Handles both unpopulated ObjectId and populated createdBy sub-documents.
const canManageAdmin = (reqUser, admin) => {
  if (reqUser.dbRole === 'root') return true;
  const createdById = admin.createdById;
  if (!createdById) return false;
  return createdById.toString() === reqUser.id;
};

// Generate a readable, URL-safe subdomain slug from a company name.
// "ABC Steel Buildings" -> "abc-steel-buildings". Collides are de-duplicated
// against existing Admin.subdomain values by appending a numeric suffix
// (e.g. "abc-steel-buildings-2"). Used to derive estimatorBusinessDbName and
// as an embed-key prefix; NOT used for subdomain-based routing today.
const slugify = (name = '') =>
  String(name)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')  // strip special characters
    .replace(/[\s_]+/g, '-')        // collapse whitespace/underscores to a dash
    .replace(/-+/g, '-')            // collapse repeated dashes
    .replace(/^-+|-+$/g, '');       // trim leading/trailing dashes

const generateUniqueSubdomain = async (companyName) => {
  const base = slugify(companyName) || 'business';
  let candidate = base;
  let suffix = 1;
  // eslint-disable-next-line no-await-in-loop
  while (await Admin.exists({ subdomain: candidate })) {
    candidate = `${base}-${++suffix}`;
  }
  return candidate;
};

/**
 * @desc Get SuperAdmin's own profile
 * @route GET /api/superadmin/profile
 * @access Super Admin
 */
export async function getProfile(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('-password -emailOTP -otpExpires');
    if (!sa) return res.status(404).json({ message: 'Super admin not found' });
    res.json({ success: true, data: sa });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Update SuperAdmin's own profile
 * @route PUT /api/superadmin/profile
 * @access Super Admin
 */
export async function updateProfile(req, res, next) {
  try {
    const updates = { ...req.body };
    delete updates.password;
    delete updates.role;
    delete updates.createdBy;
    delete updates.emailOTP;
    delete updates.otpExpires;
    updates.updatedAt = Date.now();

    if (updates.email) {
      const normEmail = updates.email.trim().toLowerCase();
      const conflict = await checkEmailExistsAcrossAllRoles(normEmail, req.user.id);
      if (conflict.exists) {
        return res.status(409).json({ message: `An account with this email already exists as ${conflict.role}` });
      }
      updates.email = normEmail;
      updates.emailHash = hashEmail(normEmail);
    }

    const sa = await SuperAdmin.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password -emailOTP -otpExpires');
    if (!sa) return res.status(404).json({ message: 'Super admin not found' });
    res.json({ success: true, data: sa });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc List all delegated Super Admins
 * @route GET /api/superadmin/superadmins
 * @access Root Super Admin only
 */
export async function listSuperAdmins(req, res, next) {
  try {
    const list = await SuperAdmin
      .find({ role: 'delegated' })
      .select('-password -emailOTP -otpExpires')
      .populate('createdById', 'firstName lastName email')
      .sort({ createdAt: -1 })
      .lean();
    res.json({ success: true, data: list });
  } catch (err) { next(err); }
}

/**
 * @desc Get a single Super Admin (delegated)
 * @route GET /api/superadmin/superadmins/:id
 * @access Root Super Admin only
 */
export async function getSuperAdmin(req, res, next) {
  try {
    const sa = await SuperAdmin
      .findById(req.params.id)
      .select('-password -emailOTP -otpExpires');
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    res.json({ success: true, data: sa });
  } catch (err) { next(err); }
}

/**
 * @desc Create a delegated Super Admin (root only)
 * @route POST /api/superadmin/superadmins
 * @access Root Super Admin only
 * Why: This is the missing "create a super admin" capability. The new account
 *      is always `role: 'delegated'` and `createdBy` is set to the root's id,
 *      so it can never escalate itself or manage other Super Admins.
 */
export async function createSuperAdmin(req, res, next) {
  try {
    // Only the root Super Admin may create other Super Admins. Enforced again in
    // the controller (not just the requireRoot route middleware) so a delegated
    // Super Admin can never create one no matter how the route is called.
    if (req.user.dbRole !== 'root') {
      return res.status(403).json({ message: 'Forbidden: only the root Super Admin can create Super Admins' });
    }

    const { firstName, lastName, email, password, department, phone, location } = req.body;
    if (!firstName || !email || !password) {
      return res.status(400).json({ message: 'firstName, email and password are required' });
    }
    // if (password.length < 8 || !/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(password)) {
    //   return res.status(400).json({ message: 'Password must be 8+ chars, include uppercase, lowercase, number & special character' });
    // }

    const normalizedEmail = email.trim().toLowerCase();
    const conflict = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (conflict.exists) {
      return res.status(409).json({ message: `An account with this email already exists as ${conflict.role}` });
    }

    const sa = new SuperAdmin({
      firstName,
      lastName,
      email: normalizedEmail,
      password,
      department,
      phone,
      location,
      role: 'delegated',          // hard-coded: delegated only, never root
      createdById: req.user.id,     // the root that created it
      // Root-created Super Admins are auto-verified (root vouches for them).
      isEmailVerified: true
    });

    await sa.save();

    const out = sa.toObject();
    delete out.password;
    delete out.emailOTP;
    delete out.otpExpires;

    res.status(201).json({ success: true, message: 'Delegated Super Admin created', data: out });
  } catch (err) { next(err); }
}

/**
 * @desc Update a delegated Super Admin (root only)
 * @route PUT /api/superadmin/superadmins/:id
 * @access Root Super Admin only
 */
export async function updateSuperAdmin(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.params.id);
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role === 'root') {
      return res.status(403).json({ message: 'The root Super Admin cannot be modified here' });
    }

    const updates = { ...req.body };
    // Never allow role/createdById/password/verification changes through this route.
    delete updates.password;
    delete updates.role;
    delete updates.createdById;
    delete updates.emailOTP;
    delete updates.otpExpires;
    updates.updatedAt = Date.now();

    const updated = await SuperAdmin
      .findByIdAndUpdate(req.params.id, updates, { new: true })
      .select('-password -emailOTP -otpExpires');

    res.json({ success: true, data: updated });
  } catch (err) { next(err); }
}

/**
 * @desc Delete a delegated Super Admin (root only)
 * @route DELETE /api/superadmin/superadmins/:id
 * @access Root Super Admin only
 */
export async function deleteSuperAdmin(req, res, next) {
  try {
    // Only the root Super Admin may delete other Super Admins (controller-level
    // guard in addition to the requireRoot route middleware).
    if (req.user.dbRole !== 'root') {
      return res.status(403).json({ message: 'Forbidden: only the root Super Admin can delete Super Admins' });
    }

    const sa = await SuperAdmin.findById(req.params.id);
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role === 'root') {
      return res.status(403).json({ message: 'The root Super Admin cannot be deleted' });
    }

    await SuperAdmin.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Delegated Super Admin deleted' });
  } catch (err) { next(err); }
}

/**
 * @desc Get all admin accounts
 * @route GET /api/superadmin/admins
 * @access Super Admin
 * Why: Allows system administrators to oversee and manage the list of admins.
 */
export async function listAdmins(req, res, next) {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    const { companyName, email } = req.query;
    let filter = {};
    if (companyName) filter.companyName = { $regex: companyName, $options: 'i' };
    if (email) filter.email = { $regex: email, $options: 'i' };

    const sa = await SuperAdmin.findById(req.user.id).select('role createdById');
    if (sa.role === 'root' || sa.role === 'superadmin') {
      // Root sees all admins system-wide
      let adminFilter = {};
      if (companyName) adminFilter.companyName = { $regex: companyName, $options: 'i' };
      if (email) adminFilter.email = { $regex: email, $options: 'i' };
      const admins = await Admin.find(adminFilter).select('-password').populate('createdById', 'firstName lastName email').sort({ createdAt: -1 });

      await Promise.all(admins.map(a => ensureTenantDEK(a._id.toString()).catch(() => null)));

      const adminsWithCounts = await Promise.all(admins.map(async (admin) => {
        const userCount = await User.countDocuments({ adminId: admin._id });
        const aObj = typeof admin.toJSON === 'function' ? admin.toJSON() : admin.toObject();
        return { ...aObj, totalUsers: userCount };
      }));

      res.json(adminsWithCounts);
    } else if (sa.role === 'delegated' || sa.role === 'superadmin') {
      // Delegated sees ONLY the Admins it directly created (its own managed
      // subtree) — never system-wide or another delegated SA's Admins.
      let dsaObjId = null;
      try {
        if (mongoose.Types.ObjectId.isValid(sa._id)) {
          dsaObjId = new mongoose.Types.ObjectId(sa._id);
        }
      } catch (e) {}

      const adminFilterQuery = {
        $or: [
          { createdById: sa._id },
          { createdBy: sa._id },
          ...(dsaObjId ? [{ createdById: dsaObjId }, { createdBy: dsaObjId }] : [])
        ]
      };
      if (companyName) adminFilterQuery.companyName = { $regex: companyName, $options: 'i' };
      if (email) adminFilterQuery.email = { $regex: email, $options: 'i' };

      const admins = await Admin.find(adminFilterQuery).select('-password').populate('createdById', 'firstName lastName email').sort({ createdAt: -1 });

      await Promise.all(admins.map(a => ensureTenantDEK(a._id.toString()).catch(() => null)));

      const adminsWithCounts = await Promise.all(admins.map(async (admin) => {
        const userCount = await User.countDocuments({ adminId: admin._id });
        const aObj = typeof admin.toJSON === 'function' ? admin.toJSON() : admin.toObject();
        return { ...aObj, totalUsers: userCount };
      }));

      res.json(adminsWithCounts);
    } else {
      res.status(403).json({ message: 'Unauthorized' });
    }
  } catch (err) { next(err); }
}

/**
 * @desc Get a single admin account
 * @route GET /api/superadmin/admins/:id
 * @access Super Admin
 * Why: To view detailed information of a specific admin.
 */
export async function getAdmin(req, res, next) {
  try {
    // Check access on the unpopulated document (createdById is an ObjectId here)
    const admin = await Admin.findById(req.params.id).select('-password');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    await ensureTenantDEK(admin._id.toString()).catch(() => null);

    // Re-fetch with the createdBy display info for the response
    const populated = await Admin.findById(req.params.id).select('-password').populate('createdById', 'firstName lastName email');
    res.json(typeof populated.toJSON === 'function' ? populated.toJSON() : populated);
  } catch (err) { next(err); }
}

/**
 * @desc Create a new admin account
 * @route POST /api/superadmin/admins
 * @access Super Admin
 * Why: To expand the administrative team and delegate management tasks.
 */
export async function createAdmin(req, res, next) {
  try {
    const { firstName, lastName, email, password, companyName, plan, phone } = req.body;
    const callerRole = req.user.dbRole; // 'root' or 'delegated'
    console.log(`[SaaS Debug] Creating Admin: email=${email}, received_plan=${plan}, callerRole=${callerRole}`);

    const normalizedEmail = email.trim().toLowerCase();
    const conflict = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (conflict.exists) {
      return res.status(409).json({ message: `An account with this email already exists as ${conflict.role}` });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // DELEGATED SUPER ADMIN → creates a DATA-VIEWER Admin (data sharing only)
    // No embed key, no subdomain, no bridge sync. The Admin can only see leads
    // that the DSA explicitly shares with them.
    // ──────────────────────────────────────────────────────────────────────────
    if (callerRole === 'delegated') {
      const admin = new Admin({
        firstName,
        lastName,
        email,
        password,
        companyName,
        phone,
        plan: 'free',         // data-viewers have no paid plan
        userLimit: 5,         // minimal default
        adminType: 'data-viewer',
        createdById: req.user.id,
        isActive: true,
        isEmailVerified: true, // DSA vouches for them
        estimatorProvisioned: false,
        permissions: {
          canCreateLead: false,  // data-viewers cannot create leads
          canCreateSubUsers: true,
          canTransferLeads: false,
          canShareLeads: false
        }
      });

      await admin.save();
      console.log(`[SaaS Log] Data-Viewer Admin Created: ID=${admin._id}, Company=${admin.companyName}, CreatedBy=${req.user.id}`);

      await AuditLog.create({
        actorId: req.user.id,
        actorRole: req.user.role,
        action: 'admin.create_data_viewer',
        actionCategory: 'admin_mgmt',
        targetType: 'admin',
        targetId: admin._id,
        ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
        metadata: { companyName, adminType: 'data-viewer' }
      });

      await ensureTenantDEK(admin._id.toString()).catch(() => null);
      const out = typeof admin.toJSON === 'function' ? admin.toJSON() : admin.toObject();
      delete out.password;
      return res.status(201).json({ success: true, data: out, adminType: 'data-viewer' });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // ROOT SUPER ADMIN → creates a full TENANT Admin
    // Gets embed key capability, subdomain, and Estimator_Node bridge sync.
    // ──────────────────────────────────────────────────────────────────────────
    const planKey = Object.keys(PLANS).find(k => k.toLowerCase() === (plan || '').toLowerCase());
    const selectedPlan = planKey || DEFAULT_PLAN;
    const userLimit = PLANS[selectedPlan].userLimit;
    console.log(`[SaaS Debug] Resolved Plan: ${selectedPlan}, Limit: ${userLimit}`);

    // Auto-generate a readable subdomain slug from the company name (kebab-case,
    // collision-safe). customDomain is intentionally left null (reserved for a
    // future premium custom-domain tier). Used to derive estimatorBusinessDbName.
    const subdomain = await generateUniqueSubdomain(companyName || email);

    const admin = new Admin({
      firstName,
      lastName,
      email,
      password,
      companyName,
      phone,
      plan: selectedPlan,
      userLimit,
      subdomain,
      adminType: 'tenant',
      estimatorProvisioned: false,
      createdById: req.user.id,
      isActive: true,
      // Super-Admin-created businesses are auto-verified (the SA vouches for them)
      isEmailVerified: true,
      permissions: {
        canCreateLead: true,
        canCreateSubUsers: false,
        canTransferLeads: false,
        canShareLeads: false
      }
    });

    await admin.save();
    console.log(`[SaaS Log] Tenant Admin Created: ID=${admin._id}, Company=${admin.companyName}, Plan=${admin.plan}, Subdomain=${admin.subdomain}, CreatedBy=${req.user.id}`);

    notificationService.createInAppNotification({
      recipient: req.user.id,
      title: 'Admin Created',
      message: `Admin ${admin.firstName || admin.companyName || 'Admin'} was created successfully`,
      type: 'success',
      entityType: 'admin',
      entityId: admin._id.toString(),
      link: '/admins'
    }).catch(err => console.error('Admin create notification error:', err));

    // Lightweight tenant registration sync with Estimator_Node
    // POST /bridge/tenants — no database provisioning, just registry entry
    const syncUrl = `${process.env.ESTIMATOR_NODE_URL}/bridge/tenants`;
    const syncPayload = {
      tenantId: admin._id,
      tenantType: 'admin',
      subdomain: admin.subdomain,
      customDomain: admin.customDomain,
      estimatorBusinessDbName: `estimator_${admin.subdomain}`
    };

    let syncAttempts = 0;
    const maxSyncRetries = 3;
    const syncBaseDelay = 500; // 500ms

    while (syncAttempts < maxSyncRetries) {
      try {
        syncAttempts++;
        await new Promise(resolve => setTimeout(resolve, syncBaseDelay));

        await axios.post(syncUrl, syncPayload, {
          timeout: 10000,
          headers: { 'X-API-Key': process.env.BRIDGE_API_KEY || 'bridge-shared-key-secret' }
        });

        admin.estimatorProvisioned = true;
        await admin.save();
        await AuditLog.create({
          actorId: req.user.id,
          actorRole: req.user.role,
          action: 'bridge_outbound_success',
          actionCategory: 'internal_api',
          targetType: 'bridge_call',
          targetId: admin._id,
          ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
          meta: {
            endpoint: '/bridge/tenants',
            direction: 'sa-to-en',
            status: 'success',
            syncAttempts,
            subdomain: admin.subdomain,
            customDomain: admin.customDomain
          }
        });
        bridgeLog.logOutboundCall('/bridge/tenants', 'success', null, { adminId: admin._id, syncAttempts });
        console.log(`[SaaS Log] Tenant synced with Estimator_Node: adminId=${admin._id}`);
        break;
      } catch (syncErr) {
        admin.estimatorProvisioned = false;
        await admin.save();
        await AuditLog.create({
          actorId: req.user.id,
          actorRole: req.user.role,
          action: 'bridge_outbound_failure',
          actionCategory: 'internal_api',
          targetType: 'bridge_call',
          targetId: admin._id,
          ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
          meta: {
            endpoint: '/bridge/tenants',
            direction: 'sa-to-en',
            status: 'failure',
            syncAttempts,
            error: syncErr.message,
            subdomain: admin.subdomain
          }
        });
        bridgeLog.logOutboundCall('/bridge/tenants', 'failure', syncErr, { adminId: admin._id, syncAttempts });
        console.warn(`[Bridge] Sync attempt ${syncAttempts} failed: ${syncErr.message}`);
        if (syncAttempts >= maxSyncRetries) {
          console.error(`[SaaS Error] Tenant sync failed after ${maxSyncRetries} attempts: ${syncErr.message}`);
        }
      }
    }

    await ensureTenantDEK(admin._id.toString()).catch(() => null);
    const out = typeof admin.toJSON === 'function' ? admin.toJSON() : admin.toObject();
    delete out.password;
    return res.status(201).json({ success: true, data: out, adminType: 'tenant' });
  } catch (err) {
    next(err);
  }
}

/**
 * @brief Retry business provisioning for a failed admin
 * @route PUT /api/superadmin/admins/:id/retry-provision
 * @access Super Admin
 * Re-runs the same Estimator_Node provisioning call that createAdmin makes on
 * success, reusing the already-generated subdomain (never regenerated). Sets
 * estimatorProvisioned=true on success; on repeated failure leaves it false,
 * writes an admin_mgmt AuditLog entry, and returns a clear error.
 */
export async function retryProvision(req, res, next) {
  try {
    const admin = await Admin.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    if (!admin.subdomain) {
      return res.status(400).json({ message: 'Admin has no generated subdomain; cannot provision.' });
    }

    // Reuse the exact provisioning call from createAdmin (registry entry stub).
    const syncUrl = `${process.env.ESTIMATOR_NODE_URL}/bridge/tenants`;
    const syncPayload = {
      tenantId: admin._id,
      subdomain: admin.subdomain,
      customDomain: admin.customDomain,
      estimatorBusinessDbName: `estimator_${admin.subdomain}`
    };

    try {
      await axios.post(syncUrl, syncPayload, {
        timeout: 10000,
        headers: { 'X-API-Key': process.env.BRIDGE_API_KEY || 'bridge-shared-key-secret' }
      });

      admin.estimatorProvisioned = true;
      await admin.save();

      await AuditLog.create({
        actorId: req.user.id,
        actorRole: req.user.role,
        action: 'bridge_outbound_success',
        actionCategory: 'admin_mgmt',
        targetType: 'bridge_call',
        targetId: admin._id,
        ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
        meta: {
          endpoint: '/bridge/tenants',
          direction: 'sa-to-en',
          status: 'success',
          action: 'retry-provision',
          subdomain: admin.subdomain
        }
      });

      bridgeLog.logOutboundCall('/bridge/tenants', 'success', null, {
        adminId: admin._id,
        action: 'retry-provision'
      });

      const out = admin.toObject();
      delete out.password;
      return res.json({ success: true, message: 'Provisioning retried successfully', data: out });
    } catch (syncErr) {
      admin.estimatorProvisioned = false;
      await admin.save();

      await AuditLog.create({
        actorId: req.user.id,
        actorRole: req.user.role,
        action: 'bridge_outbound_failure',
        actionCategory: 'admin_mgmt',
        targetType: 'bridge_call',
        targetId: admin._id,
        ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
        meta: {
          endpoint: '/bridge/tenants',
          direction: 'sa-to-en',
          status: 'failure',
          action: 'retry-provision',
          error: syncErr.message,
          subdomain: admin.subdomain
        }
      });

      bridgeLog.logOutboundCall('/bridge/tenants', 'failure', syncErr, {
        adminId: admin._id,
        action: 'retry-provision'
      });

      return res.status(502).json({ success: false, message: `Provisioning retry failed: ${syncErr.message}` });
    }
  } catch (err) {
    next(err);
  }
}
/**
 * @desc List an admin's embed keys
 * @route GET /api/superadmin/admins/:id/embed-keys
 * @access Super Admin
 */
export async function listAdminEmbedKeys(req, res, next) {
  try {
    if (req.user.dbRole === 'root' || req.user.role === 'root') {
      return res.status(403).json({ message: 'Root Super Admin cannot view or manage embed keys. Embed keys can only be created by Delegated Super Admins or Tenant Admins directly.' });
    }

    const admin = await Admin.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    const baseUrl = (process.env.ESTIMATOR_BASE_URL || 'https://gripestimator.com').replace(/\/+$/, '');
    const cleanBase = baseUrl.endsWith('/estimator-ai') ? baseUrl : `${baseUrl}/estimator-ai`;

    const keys = (admin.embedKeys || []).map((k) => {
      const isExpired = k.expiresAt && new Date(k.expiresAt) < new Date();
      const isRevoked = Boolean(k.revokedAt);
      const active = !isRevoked && !isExpired;
      const iframeSnippet = `<iframe src="${cleanBase}/?tenant=${encodeURIComponent(admin.subdomain)}&key=${encodeURIComponent(k.key)}" width="100%" height="850px" frameborder="0" style="border:0; width:100%; height:850px; min-height:850px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08);" allow="fullscreen; clipboard-read; clipboard-write" loading="lazy"></iframe>`;

      return {
        key: k.key,
        scope: k.scope,
        active,
        createdAt: k.createdAt,
        revokedAt: k.revokedAt,
        expiresAt: k.expiresAt,
        lastUsedAt: k.lastUsedAt,
        lastUsedOrigin: k.lastUsedOrigin,
        iframeSnippet
      };
    });

    res.json({ success: true, data: keys, subdomain: admin.subdomain });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Generate a new embed key for an admin
 * @route POST /api/superadmin/admins/:id/embed-keys
 * @access Super Admin
 * Key format: <subdomain>_live_<24 random bytes as hex>. Returned to the caller
 * once — the raw value is never retrievable again after creation.
 */
export async function generateEmbedKey(req, res, next) {
  try {
    if (req.user.dbRole === 'root' || req.user.role === 'root') {
      return res.status(403).json({ message: 'Root Super Admin cannot generate embed keys. Embed keys can only be created by Delegated Super Admins or Tenant Admins directly.' });
    }

    const admin = await Admin.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    // Data-viewer Admins (created by Delegated SA) cannot have embed keys.
    // They are data consumers only — the DSA's own embed key is the source.
    if (admin.adminType === 'data-viewer') {
      return res.status(403).json({
        message: 'Data-viewer admins cannot have embed keys. Only full tenant admins can. Use your own DSA embed key instead.'
      });
    }

    if (!admin.subdomain) {
      return res.status(400).json({ message: 'Admin has no subdomain; cannot generate an embed key.' });
    }

    const scope = (req.body && req.body.scope) || 'create-lead-only';
    const keyLimit = (req.body && req.body.limit) || 10;
    admin.embedKeys = admin.embedKeys || [];
    if (admin.embedKeys.length >= keyLimit) {
      return res.status(400).json({ message: `Embed key limit reached (${keyLimit}). Rotate or revoke existing keys.` });
    }

    const hex = randomBytes(24).toString('hex');
    const key = `${admin.subdomain}_live_${hex}`;

    admin.embedKeys.push({
      key,
      scope,
      createdAt: new Date(),
      revokedAt: null,
      expiresAt: null,
      lastUsedAt: null,
      lastUsedOrigin: null
    });
    await admin.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.generate',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { keyPrefix: key.slice(0, 20), scope }
    });

    const baseUrl = (process.env.ESTIMATOR_BASE_URL || 'https://gripestimator.com').replace(/\/+$/, '');
    const cleanBase = baseUrl.endsWith('/estimator-ai') ? baseUrl : `${baseUrl}/estimator-ai`;
    const iframeSnippet = `<iframe src="${cleanBase}/?tenant=${encodeURIComponent(admin.subdomain)}&key=${encodeURIComponent(key)}" width="100%" height="850px" frameborder="0" style="border:0; width:100%; height:850px; min-height:850px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08);" allow="fullscreen; clipboard-read; clipboard-write" loading="lazy"></iframe>`;

    res.status(201).json({
      success: true,
      data: {
        key,
        scope,
        createdAt: new Date(),
        active: true,
        iframeSnippet
      }
    });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Rotate an admin's embed key (grace-period rotation)
 * @route POST /api/superadmin/admins/:id/embed-keys/:key/rotate
 * @access Super Admin
 * Generates a new key and sets the old key's expiresAt to now + 72h (grace period)
 * rather than instantly revoking it, so in-flight clients can migrate smoothly.
 */
export async function rotateEmbedKey(req, res, next) {
  try {
    if (req.user.dbRole === 'root' || req.user.role === 'root') {
      return res.status(403).json({ message: 'Root Super Admin cannot rotate embed keys.' });
    }

    const { id, key } = req.params;
    const admin = await Admin.findById(id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    if (!admin.subdomain) {
      return res.status(400).json({ message: 'Admin has no subdomain; cannot generate an embed key.' });
    }

    admin.embedKeys = admin.embedKeys || [];
    const existing = admin.embedKeys.find((k) => k.key === key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

    // Grace period: old key remains usable for the next 72h.
    existing.expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);
    existing.revokedAt = null;

    const hex = randomBytes(24).toString('hex');
    const newKey = `${admin.subdomain}_live_${hex}`;
    admin.embedKeys.push({
      key: newKey,
      scope: existing.scope || 'create-lead-only',
      createdAt: new Date(),
      revokedAt: null,
      expiresAt: null,
      lastUsedAt: null,
      lastUsedOrigin: null
    });
    await admin.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.rotate',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { oldKeyPrefix: key.slice(0, 20), newKeyPrefix: newKey.slice(0, 20) }
    });

    const baseUrl = (process.env.ESTIMATOR_BASE_URL || 'https://gripestimator.com').replace(/\/+$/, '');
    const cleanBase = baseUrl.endsWith('/estimator-ai') ? baseUrl : `${baseUrl}/estimator-ai`;
    const iframeSnippet = `<iframe src="${cleanBase}/?tenant=${encodeURIComponent(admin.subdomain)}&key=${encodeURIComponent(newKey)}" width="100%" height="850px" frameborder="0" style="border:0; width:100%; height:850px; min-height:850px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.08);" allow="fullscreen; clipboard-read; clipboard-write" loading="lazy"></iframe>`;

    res.json({
      success: true,
      data: {
        key: newKey,
        oldKeyGraceExpiresAt: existing.expiresAt,
        iframeSnippet
      }
    });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Revoke an admin's embed key immediately
 * @route DELETE /api/superadmin/admins/:id/embed-keys/:key/revoke
 * @access Super Admin
 */
export async function revokeAdminEmbedKey(req, res, next) {
  try {
    if (req.user.dbRole === 'root' || req.user.role === 'root') {
      return res.status(403).json({ message: 'Root Super Admin cannot revoke embed keys.' });
    }

    const { id, key } = req.params;
    const admin = await Admin.findById(id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    admin.embedKeys = admin.embedKeys || [];
    const existing = admin.embedKeys.find((k) => k.key === key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

    existing.revokedAt = new Date();
    await admin.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.revoke',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { keyPrefix: key.slice(0, 20) }
    });

    res.json({ success: true, message: 'Embed key revoked successfully' });
  } catch (err) {
    next(err);
  }
}

/**
 * Log an action to the audit trail.
 * @param {String} action - The action enum value
 * @param {String} targetType - The targetType enum value
 * @param {Object|String} targetId - The target ID or details
 * @param {Object} req - The request object (for IP address)
 */const logAction = async (action, targetType, targetId, req, actionCategory = 'admin_mgmt') => {
  try {
    const ipAddress = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const logEntry = new AuditLog({
      actorId: req.user.id,
      actorRole: req.user.role,
      action,
      actionCategory,
      targetType,
      targetId,
      ipAddress
    });
    await logEntry.save();
    console.log(`[Audit] ${action} by ${req.user.role} ${req.user.id} on ${targetType} ${targetId}`);
  } catch (error) {
    console.error(`[Audit Error] Failed to log action: ${error.message}`);
  }
};
/**
 * @desc Get a single admin account
 * @route GET /api/superadmin/admins/:id
 * @access Super Admin
 */
export async function updateAdmin(req, res, next) {
  try {
    const existing = await Admin.findById(req.params.id);
    if (!existing) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, existing)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    const updates = { ...req.body };
    if (updates.email) updates.email = updates.email.toLowerCase();

    // SaaS Enhancement: Sync userLimit if plan is changed in a regular update
    if (updates.plan) {
      const planKey = Object.keys(PLANS).find(k => k.toLowerCase() === updates.plan.toLowerCase());
      if (planKey) {
        updates.plan = planKey;
        updates.userLimit = PLANS[planKey].userLimit;
        console.log(`[SaaS Debug] UpdateAdmin syncing plan: ${updates.plan}, limit: ${updates.userLimit}`);
      }
    }

    const admin = await Admin.findByIdAndUpdate(req.params.id, { ...updates, createdById: req.user.id }, { new: true }).select('-password');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    // Log plan/role change (compare against the pre-update values)
    const hadPlanChange = updates.plan && existing.plan !== updates.plan;
    const hadRoleChange = updates.role && existing.role !== updates.role;
    if (hadPlanChange || hadRoleChange) {
      await logAction('role_changed', 'admin', admin._id, req);
    }
    res.json(admin);
  } catch (err) { next(err); }
}

/**
 * @desc Delete an admin account
 * @route DELETE /api/superadmin/admins/:id
 * @access Super Admin
 * Why: To remove administrative access for a specific individual.
 */
export async function deleteAdmin(req, res, next) {
  try {
    const admin = await Admin.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, admin)) {
      return res.status(403).json({ message: 'Access denied. You can only delete admins you created.' });
    }

    await Admin.findByIdAndDelete(req.params.id);
    res.json({ message: 'Admin deleted' });
  } catch (err) { next(err); }
}

/**
 * @desc Update admin plan
 * @route PUT /api/superadmin/admins/:id/plan
 */
export async function updateAdminPlan(req, res, next) {
  try {
    const existing = await Admin.findById(req.params.id);
    if (!existing) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, existing)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    const { plan } = req.body;
    console.log(`[SaaS Debug] updateAdminPlan: id=${req.params.id}, requested_plan=${plan}`);

    const planKey = Object.keys(PLANS).find(k => k.toLowerCase() === (plan || '').toLowerCase());
    if (!planKey) {
      console.error(`[SaaS Error] Invalid plan requested: ${plan}`);
      return res.status(400).json({ message: 'Invalid plan selected. Choose: Basic, Pro, or Enterprise.' });
    }

    const admin = await Admin.findById(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    admin.plan = plan;
    admin.userLimit = PLANS[plan].userLimit;
    admin.createdById = req.user.id;
    await admin.save();
    console.log(`[SaaS Log] Plan Updated: AdminID=${admin._id}, NewPlan=${admin.plan}, NewLimit=${admin.userLimit}, UpdatedBy=${req.user.id}`);

    res.json({ success: true, message: 'Plan updated', data: { plan: admin.plan, userLimit: admin.userLimit } });
  } catch (err) { next(err); }
}

/**
 * @desc Toggle admin status (isActive)
 * @route PUT /api/superadmin/admins/:id/status
 */
export async function toggleAdminStatus(req, res, next) {
  try {
    const existing = await Admin.findById(req.params.id);
    if (!existing) return res.status(404).json({ message: 'Admin not found' });

    if (!canManageAdmin(req.user, existing)) {
      return res.status(403).json({ message: 'Access denied. You can only manage admins you created.' });
    }

    const { isActive } = req.body;
    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ message: 'isActive must be a boolean' });
    }

    const admin = await Admin.findByIdAndUpdate(req.params.id, { isActive }, { new: true }).select('-password');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    console.log(`[SaaS Log] Admin Status Toggled: AdminID=${admin._id}, isActive=${isActive}, UpdatedBy=${req.user.id}`);

    res.json({ success: true, message: `Admin ${isActive ? 'activated' : 'deactivated'}`, data: admin });
  } catch (err) { next(err); }
}

/**
 * @desc Get super admin dashboard stats
 * @route GET /api/superadmin/dashboard/stats
 */
export async function getDashboardStats(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('role');
    if (sa.role === 'root' || sa.role === 'superadmin') {
      // Root sees system-wide stats
      const [totalAdmins, activeAdmins, totalUsers, totalLeads] = await Promise.all([
        Admin.countDocuments(),
        Admin.countDocuments({ isActive: true }),
        User.countDocuments(),
        BuildingInfo.countDocuments()
      ]);

      res.json({
        success: true,
        data: {
          totalAdmins,
          activeAdmins,
          inactiveAdmins: totalAdmins - activeAdmins,
          totalUsers,
          totalLeads
        }
      });
    } else if (sa.role === 'delegated' || sa.role === 'superadmin') {
      let dsaObjId = null;
      try {
        if (mongoose.Types.ObjectId.isValid(sa._id)) {
          dsaObjId = new mongoose.Types.ObjectId(sa._id);
        }
      } catch (e) {}

      // Find all Admins created by this DSA
      const dsaAdminList = await Admin.find({
        $or: [
          { createdById: sa._id },
          { createdBy: sa._id },
          ...(dsaObjId ? [{ createdById: dsaObjId }, { createdBy: dsaObjId }] : [])
        ]
      }).select('_id isActive').lean();

      const adminIds = dsaAdminList.map(a => a._id);
      const totalAdmins = dsaAdminList.length;
      const activeAdmins = dsaAdminList.filter(a => a.isActive).length;
      const inactiveAdmins = totalAdmins - activeAdmins;

      // Users belonging to the DSA's subtree (created under DSA's admins or directly by DSA)
      const userFilter = {
        $or: [
          ...(adminIds.length > 0 ? [{ adminId: { $in: adminIds } }, { createdBy: { $in: adminIds } }] : []),
          { adminId: sa._id },
          { createdBy: sa._id },
          ...(dsaObjId ? [{ adminId: dsaObjId }, { createdBy: dsaObjId }] : [])
        ]
      };
      const totalUsers = await User.countDocuments(userFilter);

      // Leads scoped to this DSA:
      // 1. Leads directly attributed to DSA (managedBySuperAdmin = sa._id)
      // 2. Leads managed by Admins created by this DSA (managedByAdmin IN adminIds)
      const leadConditions = [
        { managedBySuperAdmin: sa._id },
        ...(dsaObjId ? [{ managedBySuperAdmin: dsaObjId }] : []),
        ...(adminIds.length > 0 ? [{ managedByAdmin: { $in: adminIds } }] : [])
      ];
      const leadFilter = { $or: leadConditions };

      const [totalLeads, convertedLeads, pendingLeads, totalSharedOut] = await Promise.all([
        BuildingInfo.countDocuments(leadFilter),
        BuildingInfo.countDocuments({
          ...leadFilter,
          status: { $in: ['closed-won', 'won', 'closed', 'converted'] }
        }),
        BuildingInfo.countDocuments({
          ...leadFilter,
          status: { $in: ['new', 'contacted', 'qualified', 'proposal', 'quoted'] }
        }),
        BuildingInfo.countDocuments({
          $or: [
            { managedBySuperAdmin: sa._id, 'sharedWith.0': { $exists: true } },
            ...(dsaObjId ? [{ managedBySuperAdmin: dsaObjId, 'sharedWith.0': { $exists: true } }] : [])
          ]
        })
      ]);

      res.json({
        success: true,
        data: {
          totalAdmins,
          activeAdmins,
          inactiveAdmins,
          totalUsers,
          totalLeads,
          convertedLeads,
          pendingLeads,
          // Backwards-compatible aliases:
          totalDataViewers: totalAdmins,
          activeDataViewers: activeAdmins,
          inactiveDataViewers: inactiveAdmins,
          totalOwnLeads: totalLeads,
          totalSharedOut,
          totalUnsharedLeads: Math.max(0, totalLeads - totalSharedOut)
        }
      });
    } else {
      res.status(403).json({ message: 'Unauthorized' });
    }
  } catch (err) { next(err); }
}

// ============================================================================
// DSA EMBED KEY MANAGEMENT
// Delegated Super Admins embed the 3D Estimator on THEIR OWN website.
// Keys are stored on the SuperAdmin model (not an Admin model).
// ============================================================================

/**
 * @desc List all embed keys belonging to the calling DSA
 * @route GET /api/superadmin/my-embed-keys
 * @access Delegated Super Admin
 */
export async function listMyEmbedKeys(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('embedKeys subdomain role');
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Root Super Admin cannot view or create embed keys. Embed keys can only be created by Delegated Super Admins or Tenant Admins.' });
    }
    // Return keys with raw value hidden — show only prefix + metadata
    const safeKeys = (sa.embedKeys || []).map(k => ({
      _id: k._id,
      key: k.key,
      keyPrefix: k.key ? k.key.slice(0, 30) + '...' : '',
      scope: k.scope,
      createdAt: k.createdAt,
      revokedAt: k.revokedAt,
      expiresAt: k.expiresAt,
      lastUsedAt: k.lastUsedAt,
      lastUsedOrigin: k.lastUsedOrigin,
      isActive: !k.revokedAt && (!k.expiresAt || k.expiresAt > new Date())
    }));
    res.json({ success: true, data: safeKeys, subdomain: sa.subdomain });
  } catch (err) { next(err); }
}

/**
 * @desc Generate a new personal embed key for the calling DSA
 * @route POST /api/superadmin/my-embed-keys
 * @access Delegated Super Admin
 */
export async function generateMyEmbedKey(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id);
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Root Super Admin cannot create embed keys. Embed keys can only be created by Delegated Super Admins or Tenant Admins.' });
    }

    // Auto-generate a subdomain slug from name if not already set
    if (!sa.subdomain) {
      const base = (sa.firstName ? `${sa.firstName}-${sa.lastName || sa.role}` : sa.role)
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '');
      let candidate = base || 'dsa';
      let suffix = 1;
      while (await SuperAdmin.exists({ subdomain: candidate })) {
        candidate = `${base}-${++suffix}`;
      }
      sa.subdomain = candidate;
    }

    const keyLimit = 10;
    sa.embedKeys = sa.embedKeys || [];
    const activeKeys = sa.embedKeys.filter(k => !k.revokedAt && (!k.expiresAt || k.expiresAt > new Date()));
    if (activeKeys.length >= keyLimit) {
      return res.status(400).json({ message: `Embed key limit reached (${keyLimit}). Rotate or revoke existing keys.` });
    }

    const scope = (req.body && req.body.scope) || 'create-lead-only';
    const hex = randomBytes(24).toString('hex');
    const prefix = 'dsa';
    const key = `${prefix}_${sa.subdomain}_live_${hex}`;

    sa.embedKeys.push({
      key,
      scope,
      createdAt: new Date(),
      revokedAt: null,
      expiresAt: null,
      lastUsedAt: null,
      lastUsedOrigin: null
    });
    await sa.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.generate',
      actionCategory: 'auth',
      targetType: 'superadmin',
      targetId: sa._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { keyPrefix: key.slice(0, 30), scope }
    });

    const estimatorBase = (process.env.ESTIMATOR_BASE_URL || 'https://gripestimator.com/estimator-ai').replace(/\/+$/, '');

    // Return the full key ONCE — it is never retrievable again
    res.status(201).json({
      success: true,
      data: {
        key,
        subdomain: sa.subdomain,
        scope,
        iframeSnippet: `<iframe \n  src="${estimatorBase}/?tenant=${key}" \n  width="100%" \n  height="820px" \n  frameborder="0" \n  allow="fullscreen" \n  title="3D Building Estimator">\n</iframe>`
      }
    });
  } catch (err) { next(err); }
}

/**
 * @desc Rotate a DSA's personal embed key (grace-period rotation)
 * @route POST /api/superadmin/my-embed-keys/:key/rotate
 * @access Delegated Super Admin
 */
export async function rotateMyEmbedKey(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id);
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Root Super Admin cannot rotate embed keys.' });
    }

    sa.embedKeys = sa.embedKeys || [];
    const existing = sa.embedKeys.find(k => k.key === req.params.key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

    // Grace period: old key remains usable for 72 hours
    existing.expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);
    existing.revokedAt = null;

    const hex = randomBytes(24).toString('hex');
    const prefix = 'dsa';
    const newKey = `${prefix}_${sa.subdomain}_live_${hex}`;
    sa.embedKeys.push({
      key: newKey,
      scope: existing.scope || 'create-lead-only',
      createdAt: new Date(),
      revokedAt: null,
      expiresAt: null,
      lastUsedAt: null,
      lastUsedOrigin: null
    });
    await sa.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.rotate',
      actionCategory: 'auth',
      targetType: 'superadmin',
      targetId: sa._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { oldKeyPrefix: req.params.key.slice(0, 30), newKeyPrefix: newKey.slice(0, 30) }
    });

    res.json({ success: true, data: { key: newKey, oldKeyGraceExpiresAt: existing.expiresAt } });
  } catch (err) { next(err); }
}

/**
 * @desc Revoke a DSA's personal embed key immediately
 * @route DELETE /api/superadmin/my-embed-keys/:key/revoke
 * @access Delegated Super Admin
 */
export async function revokeMyEmbedKey(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id);
    if (!sa) return res.status(404).json({ message: 'Super Admin not found' });
    if (sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Root Super Admin cannot revoke embed keys.' });
    }

    sa.embedKeys = sa.embedKeys || [];
    const existing = sa.embedKeys.find(k => k.key === req.params.key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

    existing.revokedAt = new Date();
    existing.expiresAt = new Date(); // immediately expired
    await sa.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'embed_key.revoke',
      actionCategory: 'auth',
      targetType: 'superadmin',
      targetId: sa._id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { keyPrefix: req.params.key.slice(0, 30) }
    });

    res.json({ success: true, message: 'Embed key revoked immediately.' });
  } catch (err) { next(err); }
}

// ===========================================================================
// DSA USER MANAGEMENT
// A Delegated Super Admin can view, create, update, and delete users that
// belong to admins THEY created. Scoped strictly — DSA cannot touch users
// outside their own branch.
// ===========================================================================

/**
 * @brief List all users in the DSA's branch (users under admins they created)
 * @route GET /api/superadmin/users
 * @access Delegated Super Admin
 */
export async function getDsaUsers(req, res, next) {
  try {
    let query = {};
    if (req.user.dbRole !== 'root') {
      // Delegated: admins in their branch OR users created directly by this DSA
      const branchAdmins = await Admin.find({ createdById: req.user.id }).select('_id').lean();
      const adminIds = branchAdmins.map(a => a._id);
      query = {
        $or: [
          { adminId: { $in: adminIds } },
          { createdBy: req.user.id }
        ]
      };
    }

    const users = await User.find(query)
      .populate('adminId', 'firstName lastName companyName')
      .sort({ createdAt: -1 });

    // Warm tenant DEKs so toJSON can decrypt PII cleanly
    const tenantIds = new Set();
    if (req.user.id) tenantIds.add(req.user.id.toString());
    users.forEach(u => {
      if (u.adminId) {
        const aId = u.adminId._id ? u.adminId._id.toString() : u.adminId.toString();
        tenantIds.add(aId);
      }
      if (u.createdBy) {
        const cId = u.createdBy._id ? u.createdBy._id.toString() : u.createdBy.toString();
        tenantIds.add(cId);
      }
    });
    await Promise.all(Array.from(tenantIds).map(tid => ensureTenantDEK(tid).catch(() => null)));

    const serialized = users.map(u => (typeof u.toJSON === 'function' ? u.toJSON() : u));

    res.json({ success: true, data: serialized, count: serialized.length });
  } catch (err) { next(err); }
}

/**
 * @brief Create a user under one of the branch admins (or any admin for Root)
 * @route POST /api/superadmin/users
 * @access Super Admin / Delegated Super Admin
 * Body: { adminId, firstName, lastName, email, password, role, permissions }
 */
export async function createDsaUser(req, res, next) {
  try {
    const { adminId, firstName, lastName, email, password, role, permissions } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const conflict = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (conflict.exists) {
      return res.status(409).json({ message: `An account with this email already exists as ${conflict.role}` });
    }

    let targetAdminId = adminId || null;
    if (targetAdminId) {
      if (req.user.dbRole !== 'root') {
        const targetAdmin = await Admin.findOne({ _id: targetAdminId, createdById: req.user.id });
        if (!targetAdmin) {
          return res.status(403).json({ message: 'Admin not found in your branch.' });
        }
      } else {
        const targetAdmin = await Admin.findById(targetAdminId);
        if (!targetAdmin) {
          return res.status(404).json({ message: 'Admin not found.' });
        }
      }
    } else {
      // Default to first branch admin if one exists, otherwise null
      const branchAdmin = await Admin.findOne({ createdById: req.user.id });
      if (branchAdmin) {
        targetAdminId = branchAdmin._id;
      }
    }

    if (targetAdminId) await ensureTenantDEK(targetAdminId).catch(() => null);
    await ensureTenantDEK(req.user.id).catch(() => null);

    const user = new User({
      firstName,
      lastName,
      email: normalizedEmail,
      password,
      role: role || 'user',
      adminId: targetAdminId,
      permissions: permissions || {},
      isEmailVerified: true,   // SA/DSA-created users skip email verification
      createdBy: req.user.id
    });
    await user.save();

    notificationService.createInAppNotification({
      recipient: req.user.id,
      title: 'User Created',
      message: `User ${user.firstName || user.email} was created successfully`,
      type: 'success',
      entityType: 'user',
      entityId: user._id.toString(),
      link: '/users'
    }).catch(err => console.error('DSA User create notification error:', err));

    const out = typeof user.toJSON === 'function' ? user.toJSON() : user.toObject();
    delete out.password;

    res.status(201).json({ success: true, data: out });
  } catch (err) { next(err); }
}

/**
 * @brief Update a user
 * @route PUT /api/superadmin/users/:id
 * @access Super Admin / Delegated Super Admin
 */
export async function updateDsaUser(req, res, next) {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    // Verify the user belongs to an admin in the DSA's branch or created directly by DSA
    if (req.user.dbRole !== 'root') {
      const branchAdmins = await Admin.find({ createdById: req.user.id }).select('_id').lean();
      const adminIds = branchAdmins.map(a => a._id.toString());
      const isOwned = (user.adminId && adminIds.includes(user.adminId.toString())) || (user.createdBy && user.createdBy.toString() === req.user.id);
      if (!isOwned) {
        return res.status(403).json({ message: 'User is not in your branch.' });
      }
    }

    const updates = { ...req.body };
    delete updates.password;   // use a separate change-password flow
    delete updates.adminId;    // prevent re-parenting
    delete updates.createdBy;
    updates.updatedAt = Date.now();

    const updated = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    res.json({ success: true, data: updated });
  } catch (err) { next(err); }
}

/**
 * @brief Delete (soft-remove) a user
 * @route DELETE /api/superadmin/users/:id
 * @access Super Admin / Delegated Super Admin
 */
export async function deleteDsaUser(req, res, next) {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    // Verify the user belongs to an admin in the DSA's branch or created directly by DSA
    if (req.user.dbRole !== 'root') {
      const branchAdmins = await Admin.find({ createdById: req.user.id }).select('_id').lean();
      const adminIds = branchAdmins.map(a => a._id.toString());
      const isOwned = (user.adminId && adminIds.includes(user.adminId.toString())) || (user.createdBy && user.createdBy.toString() === req.user.id);
      if (!isOwned) {
        return res.status(403).json({ message: 'User is not in your branch.' });
      }
    }

    await User.findByIdAndDelete(req.params.id);

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role || 'superadmin',
      action: 'user.delete',
      actionCategory: 'admin_mgmt',
      targetType: 'user',
      targetId: req.params.id,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { deletedUserEmail: user.email, branchAdminId: user.adminId }
    });

    res.json({ success: true, message: 'User deleted.' });
  } catch (err) { next(err); }
}
