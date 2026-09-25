import { randomBytes } from 'crypto';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import User from '../models/User.js';
import AuditLog from '../models/AuditLog.js';
import BuildingInfo from '../models/BuildingInfo.js';
import { PLANS, DEFAULT_PLAN } from '../config/plans.js';
import axios from 'axios';
import bridgeLog from '../utils/bridgeLog.js';
import { checkEmailExistsAcrossAllRoles } from '../utils/accountUniqueness.js';
import { ensureTenantDEK } from '../services/tenantCrypto.js';
import { hashEmail } from '../utils/encryption.js';

const normalizePermissions = (perms = []) => {
  const filtered = perms.filter(p => ['create-lead', 'create-sub-users', 'transfer-leads', 'share-leads'].includes(p));
  if (!filtered.includes('read')) filtered.push('read');
  return [...new Set(filtered)];
};

// Write a persisted audit entry for an admin action.
// actionCategory uses the enum on the AuditLog model (auth/user_mgmt/admin_mgmt/
// lead_mgmt/domain/settings/recovery/internal_api/other) so logs are filterable.
const recordAudit = async ({ req, action, actionCategory, targetType, targetId, meta = {} }) => {
  try {
    await AuditLog.create({
      actorId: req.user?.id,
      actorRole: req.user?.role || 'admin',
      action,
      actionCategory,
      targetType,
      targetId,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: meta
    });
  } catch (err) {
    // Audit failures must never break the primary operation.
    console.error(`[Audit Error] Failed to record ${action}:`, err.message);
  }
};

// GET /api/admin/profile
export async function getProfile(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id)
      .populate('createdById', 'firstName lastName')
      .select('-password');
    if (!admin) return res.status(404).json({ message: 'Profile not found' });
    res.json({ success: true, data: admin });
  } catch (err) {
    next(err);
  }
}

// PUT /api/admin/profile
export async function updateProfile(req, res, next) {
  try {
    const updates = { ...req.body };
    if (updates.email) {
      const normalizedEmail = updates.email.toLowerCase().trim();
      const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail, req.user.id);
      if (uniqueness.exists) {
        return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
      }
      updates.email = normalizedEmail;
    }
    delete updates.password;
    delete updates.role;
    delete updates.createdById;
    delete updates.wrappedDataKey;
    updates.updatedAt = Date.now();
    const admin = await Admin.findByIdAndUpdate(req.user.id, updates, { new: true });
    res.json({ success: true, data: admin });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/admins
export async function listAdmins(req, res, next) {
  try {
    const superAdminId = req.user.id;
    const sa = await SuperAdmin.findById(superAdminId).select('role createdById');
    if (!sa) return [];
    if (sa.role === 'delegated' && sa.createdById) {
      const admins = await Admin.find({ createdById: { $in: [superAdminId, sa.createdById] } }, '_id').lean();
      return admins.map((a) => a._id);
    }
    const admins = await Admin.find({ createdById: superAdminId }, '_id').lean();
    return admins.map((a) => a._id);
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/admins/:id
export async function getAdmin(req, res, next) {
  try {
    const admin = await Admin.findById(req.params.id).select('-password');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    res.json({ success: true, data: admin });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/admins
export async function createAdmin(req, res, next) {
  try {
    const { firstName, lastName, email, password, companyName, plan } = req.body;
    console.log('[SaaS Debug] Creating Admin: email=%s, received_plan=%s', email, plan);

    if (!email) return res.status(400).json({ message: 'Email is required' });
    const normalizedEmail = email.toLowerCase().trim();

    const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (uniqueness.exists) {
      return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
    }

    const planKey = Object.keys(PLANS).find(k => k.toLowerCase() === (plan || '').toLowerCase());
    const selectedPlan = planKey || DEFAULT_PLAN;
    const userLimit = PLANS[selectedPlan].userLimit;

    const admin = new Admin({
      firstName,
      lastName,
      email,
      password,
      companyName,
      plan: selectedPlan,
      userLimit,
      createdById: req.user.id,     // the root that created it
      isActive: true,
      // Super-Admin-created businesses are auto-verified (the SA vouches for them)
      isEmailVerified: true
    });

    await admin.save();
    console.log('[SaaS Log] Admin Created: ID=%s, Company=%s, Plan=%s, CreatedBy=%s', admin._id, admin.companyName, admin.plan, req.user.id);

    // Lightweight tenant registration sync with Estimator_Node
    // POST /bridge/tenants -- no database provisioning, just registry entry
    const syncUrl = process.env.ESTIMATOR_NODE_URL + '/bridge/tenants';
    const syncPayload = {
      tenantId: admin._id,
      subdomain: admin.subdomain,
      customDomain: admin.customDomain
    };

    let syncError = null;
    let syncAttempts = 0;
    const maxSyncRetries = 3;
    const syncBaseDelay = 500; // 500ms

    while (syncAttempts < maxSyncRetries) {
      try {
        syncAttempts++;
        await new Promise(resolve => setTimeout(resolve, syncBaseDelay));
        await axios.post(syncUrl, syncPayload);
        break; // success
      } catch (err) {
        syncError = err;
      }
    }

    if (syncError && syncAttempts === maxSyncRetries) {
      console.log('[SaaS Error] Tenant sync failed after %d attempts: %s', maxSyncRetries, syncError.message);
    }

    res.status(201).json({ success: true, data: admin });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/dashboard — admin's own team + leads (desc)
export async function getDashboard(req, res, next) {  
  try {
    const admin = await Admin.findById(req.user.id).select('-password');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    
    const [totalUsers, activeUsers, totalLeads, wonLeads, activeLeads, recentLeads] = await Promise.all([
      User.countDocuments({ adminId: admin._id }),
      User.countDocuments({ adminId: admin._id, isActive: true }),
      BuildingInfo.countDocuments({ managedByAdmin: admin._id }),
      BuildingInfo.countDocuments({ managedByAdmin: admin._id, status: { $in: ['closed-won', 'closed', 'converted'] } }),
      BuildingInfo.countDocuments({ managedByAdmin: admin._id, status: { $nin: ['closed-won', 'closed-lost', 'closed', 'converted'] } }),
      BuildingInfo.find({ managedByAdmin: admin._id }).sort({ createdAt: -1 }).limit(5).lean()
    ]);
    
    res.json({
      success: true,
      data: {
        admin,
        statistics: { totalUsers, activeUsers, totalLeads, wonLeads, activeLeads },
        totalUsers,
        recentLeads
      }
    });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/users
export async function listUsers(req, res, next) {
  try {
    const adminId = req.user.id;
    await ensureTenantDEK(adminId).catch(() => null);
    const users = await User.find({ adminId }).select('-password').sort({ createdAt: -1 });
    const serializedUsers = users.map(user => {
      const uObj = typeof user.toJSON === 'function' ? user.toJSON() : user.toObject();
      return {
        ...uObj,
        statistics: {
          leadCount: 0,
          wonLeads: 0
        }
      };
    });
    res.json({ success: true, data: serializedUsers });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/users/:id
export async function getUser(req, res, next) {
  try {
    await ensureTenantDEK(req.user.id).catch(() => null);
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ success: true, data: typeof user.toJSON === 'function' ? user.toJSON() : user });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/users
export async function createUser(req, res, next) {
  try {
    const { firstName, lastName, email, password, companyName, plan } = req.body;
    console.log('[SaaS Debug] Creating User: email=%s, received_plan=%s', email, plan);

    if (!email) return res.status(400).json({ message: 'Email is required' });
    const normalizedEmail = email.toLowerCase().trim();

    const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (uniqueness.exists) {
      return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
    }

    const planKey = Object.keys(PLANS).find(k => k.toLowerCase() === (plan || '').toLowerCase());
    const selectedPlan = planKey || DEFAULT_PLAN;
    const userLimit = PLANS[selectedPlan].userLimit;

    const user = new User({
      firstName,
      lastName,
      email: normalizedEmail,
      password,
      adminId: req.user.id,
      role: 'user',
      isEmailVerified: true,
      permissions: {
        canCreateLead: false,
        canCreateSubUsers: false,
        canTransferLeads: false,
        canShareLeads: false
      }
    });

    await user.save();
    console.log('[SaaS Log] User Created: ID=%s, Company=%s, Plan=%s, CreatedBy=%s', user._id, user.companyName, user.plan, req.user.id);

    // Warm tenant DEK for response
    await ensureTenantDEK(req.user.id).catch(() => null);

    await recordAudit({
      req,
      action: 'user.create',
      actionCategory: 'user_mgmt',
      targetType: 'user',
      targetId: user._id,
      meta: { email: normalizedEmail, createdBy: req.user?.id || '' }
    });

    res.status(201).json({ success: true, data: user.toJSON() });
  } catch (err) {
    next(err);
  }
}

// PUT /api/admin/users/:id
export async function updateUser(req, res, next) {
  try {
    const { firstName, lastName, email, password } = req.body;
    const updates = { ...req.body };
    delete updates.password;

    if (updates.email) {
      const normalizedEmail = updates.email.trim().toLowerCase();
      const conflict = await checkEmailExistsAcrossAllRoles(normalizedEmail, req.params.id);
      if (conflict.exists) {
        return res.status(409).json({ message: conflict.message || 'An account with this email already exists.' });
      }
      updates.email = normalizedEmail;
      updates.emailHash = hashEmail(normalizedEmail);
    }

    await ensureTenantDEK(req.user.id).catch(() => null);
    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    await recordAudit({
      req,
      action: 'user.update',
      actionCategory: 'user_mgmt',
      targetType: 'user',
      targetId: user._id,
      meta: { email: user.email || '' }
    });
    res.json({ success: true, data: typeof user.toJSON === 'function' ? user.toJSON() : user });
  } catch (err) {
    next(err);
  }
}

// DELETE /api/admin/users/:id
export async function deleteUser(req, res, next) {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ success: true, message: 'User deleted successfully' });
  } catch (err) {
    next(err);
  }
}

// GET /admin/users/:id/buildings
export async function getUserBuildings(req, res, next) {
  try {
    const buildings = await BuildingInfo.find({ owner: req.params.id }).select('-password').sort({ createdAt: -1 });
    res.json({ success: true, data: buildings });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/assign-leads
export async function adminAssignUsersToLeads(req, res, next) {
  try {
    const userId = req.params.userId || req.body.userId;
    const { leads } = req.body;

    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    if (!Array.isArray(leads)) {
      return res.status(400).json({ message: 'Leads array required' });
    }

    const selectedLeadIds = leads.map(l => l.leadId.toString());

    let leadFilter = {};
    if (req.user.role === 'superadmin' || req.user.role === 'delegated') {
      if (req.user.dbRole === 'root') {
        leadFilter = {};
      } else {
        const dsaAdminIds = await Admin.find({ createdById: req.user.id }).select('_id').lean();
        const adminIdList = dsaAdminIds.map(a => a._id);
        leadFilter = {
          $or: [
            { managedBySuperAdmin: req.user.id },
            { managedByAdmin: req.user.id },
            { managedByAdmin: { $in: adminIdList } }
          ]
        };
      }
    } else {
      leadFilter = {
        $or: [
          { managedByAdmin: req.user.id },
          { 'sharedWith.adminId': req.user.id }
        ]
      };
    }

    const allLeads = await BuildingInfo.find(leadFilter);

    for (let building of allLeads) {
      const isSelected = selectedLeadIds.includes(building._id.toString());

      const existingIndex = building.assignedUsers.findIndex(
        u => (u.user?._id || u.user).toString() === userId.toString()
      );

      if (isSelected) {
        const leadData = leads.find(
          l => l.leadId.toString() === building._id.toString()
        );

        const safePermissions = normalizePermissions(
          leadData?.permissions || ['read']
        );

        if (existingIndex !== -1) {
          building.assignedUsers[existingIndex].permissions = safePermissions;
        } else {
          building.assignedUsers.push({
            user: userId,
            permissions: safePermissions
          });
        }
      } else {
        if (existingIndex !== -1) {
          building.assignedUsers.splice(existingIndex, 1);
        }
      }

      await building.save();
    }

    await recordAudit({
      req,
      action: 'lead.assign',
      actionCategory: 'lead_mgmt',
      targetType: 'user',
      targetId: req.params.userId || req.body.userId || req.user.id,
      meta: { leadCount: String(selectedLeadIds.length), leadIds: selectedLeadIds.join(',') }
    });

    res.json({
      success: true,
      message: 'Leads assigned successfully'
    });
  } catch (err) {
    next(err);
  }
}

// PUT /api/admin/update-permission
export async function updateUserPermission(req, res, next) {
  try {
    const { userId, permissions } = req.body;
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const safePermissions = normalizePermissions(permissions);
    user.permissions = safePermissions;
    await user.save();

    res.json({
      success: true,
      data: { userId, permissions: safePermissions }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/verify-domain
export async function verifyDomain(req, res, next) {
  try {
    const { domain } = req.body;
    // Basic domain verification - check if domain is valid format
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({ message: 'Invalid domain format' });
    }
    await recordAudit({
      req,
      action: 'domain.verify',
      actionCategory: 'domain',
      targetType: 'admin',
      targetId: req.user?.id,
      meta: { domain }
    });
    res.json({
      success: true,
      data: { domain, verified: true }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/check-domain
export async function checkDomain(req, res, next) {
  try {
    const { domain } = req.body;
    const existing = await Admin.findOne({ customDomain: domain });
    res.json({
      success: true,
      data: { domain, exists: !!existing }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/sync-domain-to-estimator
export async function syncDomainToEstimator(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    const syncUrl = process.env.ESTIMATOR_NODE_URL + '/bridge/tenants';
    const syncPayload = {
      tenantId: admin._id,
      subdomain: admin.subdomain,
      customDomain: admin.customDomain
    };

    await new Promise(resolve => setTimeout(resolve, 500));
    await axios.post(syncUrl, syncPayload);

    res.json({
      success: true,
      data: { message: 'Domain synced to estimator' }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/export-lead/:leadId
export async function exportLead(req, res, next) {
  try {
    const { leadId } = req.params;
    const building = await BuildingInfo.findById(leadId);
    if (!building) return res.status(404).json({ message: 'Lead not found' });

    res.json({
      success: true,
      data: { leadId, buildingType: building.buildingType }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/erase-lead/:leadId
export async function eraseLead(req, res, next) {
  try {
    const { leadId } = req.params;
    const lead = await BuildingInfo.findById(leadId);
    if (lead && lead.estimatorBuildingId) {
      try {
        const { default: mongoose } = await import('mongoose');
        const estId = String(lead.estimatorBuildingId);
        const col = mongoose.connection.db.collection('buildings');
        if (mongoose.Types.ObjectId.isValid(estId)) {
          await col.deleteOne({ _id: new mongoose.Types.ObjectId(estId) });
        }
        await col.deleteOne({ _id: estId });
      } catch (cascadeErr) {
        console.warn('[ErasureCascade] Failed to delete raw building:', cascadeErr.message);
      }
    }
    const removed = await BuildingInfo.findByIdAndDelete(leadId);
    // Only decrement when the record was actually removed from the leads collection.
    if (removed && removed.managedByAdmin) await Admin.decrementTotalLeads(removed.managedByAdmin);
    res.json({
      success: true,
      data: { leadId, message: 'Lead erased successfully' }
    });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/leads/export
export async function exportAllLeads(req, res, next) {
  try {
    const buildings = await BuildingInfo.find({ managedByAdmin: req.user.id }).select('buildingType userInfo.firstName userInfo.lastName status').sort({ createdAt: -1 });
    res.json({
      success: true,
      data: buildings
    });
  } catch (err) {
    next(err);
  }
}

// GET /api/admin/leads/erase
export async function eraseAllLeads(req, res, next) {
  try {
    const result = await BuildingInfo.deleteMany({ managedByAdmin: req.user.id });
    // Bulk hard delete -> decrement by how many were actually removed.
    if (result.deletedCount > 0) await Admin.decrementTotalLeads(req.user.id, result.deletedCount);
    res.json({
      success: true,
      data: { message: 'All leads erased successfully' }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/admin/test-email
export async function testEmail(req, res, next) {
  try {
    res.json({
      success: true,
      data: { message: 'Test email endpoint working' }
    });
  } catch (err) {
    next(err);
  }
}

// DELETE /api/admin/admins/:id
export async function deleteAdmin(req, res, next) {
  try {
    const admin = await Admin.findByIdAndDelete(req.params.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    res.json({ success: true, message: 'Admin deleted successfully' });
  } catch (err) {
    next(err);
  }
}

// ===================== EMBED KEY MANAGEMENT (TENANT ADMINS) =====================

/**
 * Helper to generate a unique subdomain for an Admin if not yet provisioned.
 */
const generateUniqueAdminSubdomain = async (companyName) => {
  const base = String(companyName || 'business')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/[\s_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '') || 'business';
  let candidate = base;
  let suffix = 1;
  while (await Admin.exists({ subdomain: candidate })) {
    candidate = `${base}-${++suffix}`;
  }
  return candidate;
};

/**
 * @desc List all embed keys belonging to the calling Tenant Admin (created by RSA)
 * @route GET /api/admin/my-embed-keys
 * @access Tenant Admin
 */
export async function listMyEmbedKeys(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id).select('embedKeys subdomain adminType');
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    if (admin.adminType === 'data-viewer') {
      return res.status(403).json({
        message: 'Data-viewer admins cannot have embed keys. Only full tenant admins created by Root Super Admin can generate embed keys.'
      });
    }

    const safeKeys = (admin.embedKeys || []).map(k => ({
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

    res.json({ success: true, data: safeKeys, subdomain: admin.subdomain });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Generate a new embed key for the calling Tenant Admin (created by RSA)
 * @route POST /api/admin/my-embed-keys
 * @access Tenant Admin
 */
export async function generateMyEmbedKey(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    if (admin.adminType === 'data-viewer') {
      return res.status(403).json({
        message: 'Data-viewer admins cannot have embed keys. Only full tenant admins created by Root Super Admin can generate embed keys.'
      });
    }

    if (!admin.subdomain) {
      admin.subdomain = await generateUniqueAdminSubdomain(admin.companyName || admin.firstName);
    }

    const keyLimit = 10;
    admin.embedKeys = admin.embedKeys || [];
    const activeKeys = admin.embedKeys.filter(k => !k.revokedAt && (!k.expiresAt || k.expiresAt > new Date()));
    if (activeKeys.length >= keyLimit) {
      return res.status(400).json({ message: `Embed key limit reached (${keyLimit}). Rotate or revoke existing keys.` });
    }

    const scope = (req.body && req.body.scope) || 'create-lead-only';
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

    await recordAudit({
      req,
      action: 'embed_key.generate',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      meta: { keyPrefix: key.slice(0, 30), scope }
    });

    const estimatorBase = (process.env.ESTIMATOR_BASE_URL || 'https://gripestimator.com/estimator-ai').replace(/\/+$/, '');

    res.status(201).json({
      success: true,
      data: {
        key,
        subdomain: admin.subdomain,
        scope,
        iframeSnippet: `<iframe \n  src="${estimatorBase}/?tenant=${key}" \n  width="100%" \n  height="820px" \n  frameborder="0" \n  allow="fullscreen" \n  title="3D Building Estimator">\n</iframe>`
      }
    });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Rotate a Tenant Admin's embed key (grace-period rotation)
 * @route POST /api/admin/my-embed-keys/:key/rotate
 * @access Tenant Admin
 */
export async function rotateMyEmbedKey(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    if (admin.adminType === 'data-viewer') {
      return res.status(403).json({
        message: 'Data-viewer admins cannot have embed keys. Only full tenant admins created by Root Super Admin can rotate embed keys.'
      });
    }

    admin.embedKeys = admin.embedKeys || [];
    const existing = admin.embedKeys.find(k => k.key === req.params.key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

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

    await recordAudit({
      req,
      action: 'embed_key.rotate',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      meta: { oldKeyPrefix: req.params.key.slice(0, 30), newKeyPrefix: newKey.slice(0, 30) }
    });

    res.json({ success: true, data: { key: newKey, oldKeyGraceExpiresAt: existing.expiresAt } });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Revoke a Tenant Admin's embed key immediately
 * @route DELETE /api/admin/my-embed-keys/:key/revoke
 * @access Tenant Admin
 */
export async function revokeMyEmbedKey(req, res, next) {
  try {
    const admin = await Admin.findById(req.user.id);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });
    if (admin.adminType === 'data-viewer') {
      return res.status(403).json({
        message: 'Data-viewer admins cannot have embed keys.'
      });
    }

    admin.embedKeys = admin.embedKeys || [];
    const existing = admin.embedKeys.find(k => k.key === req.params.key);
    if (!existing) return res.status(404).json({ message: 'Embed key not found' });

    existing.revokedAt = new Date();
    existing.expiresAt = new Date();
    await admin.save();

    await recordAudit({
      req,
      action: 'embed_key.revoke',
      actionCategory: 'auth',
      targetType: 'admin',
      targetId: admin._id,
      meta: { keyPrefix: req.params.key.slice(0, 30) }
    });

    res.json({ success: true, message: 'Embed key revoked immediately.' });
  } catch (err) {
    next(err);
  }
}
