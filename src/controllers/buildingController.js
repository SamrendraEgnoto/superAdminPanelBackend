
import mongoose from 'mongoose';
import BuildingInfo from '../models/BuildingInfo.js';
import User from '../models/User.js';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import notificationService from '../utils/notificationService.js';
import { allowRoles } from '../middlewares/roles.js';
import { buildCustomerRightsLink } from '../utils/customerToken.js';
import { resolveEmbedKey } from '../middlewares/embedKeyAuth.js';
import { ensureTenantDEK } from '../services/tenantCrypto.js';

// ############################ HELPERS ############################

const VALID_PERMISSIONS = ['read', 'edit', 'delete'];

const normalizePermissions = (perms = []) => {
  const filtered = perms.filter(p => VALID_PERMISSIONS.includes(p));
  if (filtered.includes('edit') && !filtered.includes('delete')) {
    filtered.push('delete');
  }

  if (!filtered.includes('read')) filtered.push('read');
  return [...new Set(filtered)];
};

const getAssignedUser = (building, userId) => {
  return building.assignedUsers.find(
    (a) => a.user.toString() === userId
  );
};

const hasPermission = (assignedUser, permission) => {
  return assignedUser?.permissions?.includes(permission);
};

// ############################ VALIDATION ############################
export async function validateSchema(req, res, next) {
  const { buildingType, userInfo } = req.body;

  if (!buildingType || !userInfo) {
    return res.status(400).json({ message: 'buildingType and userInfo required' });
  }

  next();
}

// ############################ CREATE LEAD ############################
export async function createBuilding(req, res, next) {
  try {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    if (req.user.role === 'root' || req.user.dbRole === 'root') {
      return res.status(403).json({ message: 'Root Super Admin manages platform admins and delegated super admins, not individual leads.' });
    }

    const { buildingType, userInfo } = req.body;
    if (!buildingType || !userInfo) {
      return res.status(400).json({
        message: 'buildingType and userInfo are required'
      });
    }

    // Determine ownership so a lead is never orphaned at the Super Admin level:
    //  - admin     -> managed by this admin; SA-owner recorded via managedBySuperAdmin
    //  - superadmin -> owned DIRECTLY via managedBySuperAdmin (no admin required)
    //  - user      -> managed by the user's admin; owned by the user
    let managedByAdmin;
    let managedBySuperAdmin;
    let owner = null;
    let assignedUsers = [];

    if (req.user.role === 'admin') {
      // Full tenant admin creates a lead scoped to themselves.
      // managedBySuperAdmin points to whoever created this admin (RSA or DSA).
      managedByAdmin = req.user.id;
      managedBySuperAdmin = req.user.createdBy || null;
    } else if (req.user.role === 'superadmin') {
      // SuperAdmin creates lead directly; optionally assigns it to an admin.
      managedBySuperAdmin = req.user.id;
      const { adminId } = req.body;
      if (adminId) {
        const targetAdmin = await Admin.findById(adminId);
        if (!targetAdmin) {
          return res.status(404).json({ message: 'Target Admin not found' });
        }
        managedByAdmin = adminId;
      } else {
        managedByAdmin = null;
      }
    } else {
      // user — creates lead under their own admin's umbrella.
      managedByAdmin = req.user.adminId;
      const owningAdmin = await Admin.findById(req.user.adminId).select('createdById');
      // createdById is the DSA/RSA that provisioned this admin.
      managedBySuperAdmin = owningAdmin?.createdById || null;
      owner = req.user.id;
      assignedUsers = [
        {
          user: req.user.id,
          permissions: normalizePermissions(['edit', 'delete'])
        }
      ];
    }

    const newLead = new BuildingInfo({
      ...req.body,
      managedByAdmin,
      managedBySuperAdmin,
      owner,
      assignedUsers
    });

    await newLead.save();

    // Keep the owning admin's lead counter in sync (atomic $inc).
    if (managedByAdmin) await Admin.incrementTotalLeads(managedByAdmin);

    // Trigger in-app + email notification for the new lead
    const rawCustomerName = (`${userInfo.firstName || ''} ${userInfo.lastName || ''}`.trim() || userInfo.customerName || userInfo.email || '').trim();
    notificationService.notifyLeadArrival(newLead, { 
      admin: managedByAdmin, 
      superAdmin: managedBySuperAdmin,
      rawCustomerName
    }).catch(err => console.error('Lead arrival notification error:', err));

    // Attach the lead-scoped customer-rights token + link so the caller (or the
    // confirmation email builder) can give the customer access to their data.
    return res.status(201).json({
      success: true,
      data: newLead,
      ...buildCustomerRightsLink(newLead._id)
    });

  } catch (err) {
    console.error('CREATE BUILDING ERROR:', err);
    next(err);
  }
}

// ############################ CREATE PUBLIC LEAD (FROM ESTIMATOR) ############################
export async function createPublicBuilding(req, res, next) {
  try {
    const rawUserInfo = req.body.userInfo || req.body.customer || {};
    const buildingType = req.body.buildingType || req.body.type || 'commercial';

    // Normalize userInfo fields
    let firstName = rawUserInfo.firstName || req.body.firstName || '';
    let lastName = rawUserInfo.lastName || req.body.lastName || '';
    const fullName = rawUserInfo.customerName || req.body.customerName || rawUserInfo.name || req.body.name || '';
    if (!firstName && fullName) {
      const parts = fullName.trim().split(/\s+/);
      firstName = parts[0] || '';
      lastName = parts.slice(1).join(' ') || '';
    }

    const userInfo = {
      firstName,
      lastName,
      email: rawUserInfo.email || rawUserInfo.customerEmail || req.body.email || req.body.customerEmail || '',
      phoneNumber: rawUserInfo.phoneNumber || rawUserInfo.phone || rawUserInfo.customerPhone || req.body.phoneNumber || req.body.phone || '',
      phone: rawUserInfo.phone || rawUserInfo.phoneNumber || rawUserInfo.customerPhone || req.body.phone || req.body.phoneNumber || '',
      address: rawUserInfo.address || req.body.address || '',
      city: rawUserInfo.city || req.body.city || '',
      state: rawUserInfo.state || req.body.state || '',
      zip: rawUserInfo.zip || rawUserInfo.zipCode || req.body.zip || req.body.zipCode || '',
      notes: rawUserInfo.notes || req.body.notes || ''
    };

    if (!userInfo.email && !userInfo.phoneNumber && !userInfo.firstName) {
      return res.status(400).json({
        message: 'Customer information (email, phone, or name) is required'
      });
    }

    // Extract tenant identifier / embed key from all possible locations
    const keyCandidate =
      (req.headers && req.headers['x-embed-key']) ||
      (req.headers && req.headers['x-tenant-key']) ||
      (req.headers && req.headers['x-tenant-id']) ||
      (req.headers && req.headers['x-admin-id']) ||
      (req.headers && req.headers['tenant-id']) ||
      (req.headers && req.headers['tenant']) ||
      req.body.key ||
      req.body.tenant ||
      req.body.tenantId ||
      req.body.tenant_id ||
      req.body.tenantKey ||
      req.body.tenant_key ||
      req.body.adminId ||
      req.body.admin_id ||
      req.body.managedByAdmin ||
      req.body.superAdminId ||
      req.body.super_admin_id ||
      req.body.embedKey ||
      req.body.embed_key ||
      req.body.attributes?.tenant ||
      req.body.attributes?.tenantId ||
      req.body.attributes?.tenant_id ||
      req.body.attributes?.embedKey ||
      req.body.attributes?.embed_key ||
      req.body.attributes?.key ||
      req.body.userInfo?.tenant ||
      req.body.userInfo?.tenantId ||
      req.body.userInfo?.tenant_id ||
      req.body.userInfo?.embedKey ||
      req.body.userInfo?.key ||
      req.query.key ||
      req.query.tenant ||
      req.query.tenantId ||
      req.query.tenant_id ||
      req.query.embedKey ||
      req.query.embed_key;

    let managedByAdmin = null;
    let managedBySuperAdmin = null;

    if (keyCandidate) {
      const keyStr = String(keyCandidate).trim();
      const resolved = await resolveEmbedKey(keyStr).catch(() => null);
      if (resolved && resolved.valid) {
        if (resolved.isSuperAdmin) {
          managedBySuperAdmin = resolved.superAdminId;
        } else {
          managedByAdmin = resolved.adminId;
          const owningAdmin = await Admin.findById(resolved.adminId).select('createdById createdBy');
          managedBySuperAdmin = owningAdmin?.createdById || owningAdmin?.createdBy || null;
        }
      } else if (/^[0-9a-f]{24}$/i.test(keyStr)) {
        // Direct ObjectId fallback: Check SuperAdmin first, then Admin
        const sa = await SuperAdmin.findById(keyStr).select('_id');
        if (sa) {
          managedBySuperAdmin = sa._id;
        } else {
          const adm = await Admin.findById(keyStr).select('_id createdById createdBy');
          if (adm) {
            managedByAdmin = adm._id;
            managedBySuperAdmin = adm.createdById || adm.createdBy || null;
          }
        }
      } else {
        // Fallback: Match by subdomain (e.g. "abc", "nikhil-dev")
        const adm = await Admin.findOne({ subdomain: keyStr.toLowerCase() }).select('_id createdById createdBy');
        if (adm) {
          managedByAdmin = adm._id;
          managedBySuperAdmin = adm.createdById || adm.createdBy || null;
        }
      }
    }

    // Ensure either managedByAdmin or managedBySuperAdmin was identified
    if (!managedByAdmin && !managedBySuperAdmin) {
      return res.status(400).json({
        success: false,
        message: 'Valid X-Embed-Key or tenant identifier is required to attribute this lead.'
      });
    }

    // Warm tenant DEK for encryption pre('save')
    const tenantIdToWarm = managedByAdmin || managedBySuperAdmin;
    if (tenantIdToWarm) {
      await ensureTenantDEK(tenantIdToWarm.toString()).catch(() => null);
    }

    const newLead = new BuildingInfo({
      buildingType,
      userInfo,
      attributes: req.body.attributes,
      managedByAdmin,
      managedBySuperAdmin,
      source: req.body.source || 'website',
      status: 'new',
      estimatorBuildingId: req.body.estimatorBuildingId || undefined,
      consentGiven: typeof req.body.consentGiven === 'boolean' ? req.body.consentGiven : undefined,
      consentTimestamp: req.body.consentTimestamp ? new Date(req.body.consentTimestamp) : undefined,
      consentTextVersion: req.body.consentTextVersion ? String(req.body.consentTextVersion) : undefined
    });

    await newLead.save();

    // Increment admin's lead counter if owned by admin
    if (managedByAdmin) await Admin.incrementTotalLeads(managedByAdmin);

    // =============== NOTIFICATIONS ===============
    const rawCustomerName = (fullName || `${firstName} ${lastName}`.trim() || userInfo.email || '').trim();
    Promise.all([
      managedByAdmin ? Admin.findById(managedByAdmin) : null,
      managedBySuperAdmin ? SuperAdmin.findById(managedBySuperAdmin) : null
    ]).then(([targetAdmin, targetSA]) => {
      notificationService.notifyLeadArrival(newLead, { 
        admin: targetAdmin || managedByAdmin, 
        superAdmin: targetSA || managedBySuperAdmin,
        rawCustomerName
      });
    }).catch(err => console.error('Public lead notification error:', err));
    // =============================================

    return res.status(201).json({
      success: true,
      data: newLead,
      ...buildCustomerRightsLink(newLead._id)
    });

  } catch (err) {
    console.error('CREATE PUBLIC BUILDING ERROR:', err);
    next(err);
  }
}

// ############################ GET ALL LEADS ############################
export async function getBuildings(req, res, next) {
  try {
    let filter = {};

    if (req.user.role === 'admin') {
      // Check if this is a data-viewer admin (created by DSA for data sharing only)
      // or a full tenant admin (created by Root/DSA with embed key).
      const callerAdmin = await Admin.findById(req.user.id).select('adminType');
      if (callerAdmin && callerAdmin.adminType === 'data-viewer') {
        // Data-viewer: can ONLY see leads explicitly shared to them by their DSA
        filter = { 'sharedWith.adminId': req.user.id };
      } else {
        // Full tenant admin: sees all leads managed by them.
        filter.managedByAdmin = req.user.id;
      }
    } else if (req.user.role === 'user') {
      const userDoc = await User.findById(req.user.id).select('adminId createdBy').lean();
      const parentAdminId = req.user.adminId || userDoc?.adminId;
      const parentCreatorId = req.user.createdBy || userDoc?.createdBy;

      const parentScope = [];
      if (parentAdminId) {
        parentScope.push({ managedByAdmin: parentAdminId });
        parentScope.push({ 'sharedWith.adminId': parentAdminId });
      }
      if (parentCreatorId) {
        parentScope.push({ managedBySuperAdmin: parentCreatorId });
        parentScope.push({ managedByAdmin: parentCreatorId });
      }

      filter = {
        $and: [
          ...(parentScope.length > 0 ? [{ $or: parentScope }] : []),
          {
            $or: [
              { owner: req.user.id },
              { 'assignedUsers.user': req.user.id }
            ]
          }
        ]
      };
    } else if (req.user.role === 'superadmin') {
      if (req.user.dbRole === 'root') {
        // Root Super Admin: sees ALL leads across the platform.
        filter = {};
      } else {
        // Delegated Super Admin: sees leads from:
        //   1. Admins THEY created (managedByAdmin IN [their admin IDs]), or
        //   2. Leads directly attributed to them (managedBySuperAdmin = dsaId)
        const dsaId = req.user.id;
        let dsaObjId = null;
        try {
          if (mongoose.Types.ObjectId.isValid(dsaId)) {
            dsaObjId = new mongoose.Types.ObjectId(dsaId);
          }
        } catch (e) {}

        const dsaAdminIds = await Admin.find({
          $or: [
            { createdById: dsaId },
            ...(dsaObjId ? [{ createdById: dsaObjId }] : [])
          ]
        }).select('_id').lean();
        const adminIdList = dsaAdminIds.map(a => a._id);
        filter = {
          $or: [
            { managedByAdmin: { $in: adminIdList } },
            { managedBySuperAdmin: dsaId },
            ...(dsaObjId ? [{ managedBySuperAdmin: dsaObjId }] : [])
          ]
        };
      }
    }

    const leads = await BuildingInfo.find(filter)
      .populate('owner', 'firstName lastName')
      .populate('assignedUsers.user', 'firstName lastName email')
      .sort({ updatedAt: -1 });

    // Warm tenant DEKs for all tenants present in these leads so toJSON / getEmail / getPhone can decrypt
    const tenantIds = [
      ...new Set(
        leads
          .map((l) => (l.managedByAdmin || l.managedBySuperAdmin || '').toString())
          .filter(Boolean)
      )
    ];
    if (req.user?.id) tenantIds.push(req.user.id.toString());
    await Promise.all(tenantIds.map((tid) => ensureTenantDEK(tid).catch(() => null)));

    const updatedLeads = leads.map((lead) => {
      let currentUserPermissions = [];
      if (req.user.role === 'admin' || req.user.role === 'superadmin') {
        currentUserPermissions = ['read', 'edit', 'delete'];
      } else {
        // User permissions determined by the permissions object on the user model
        currentUserPermissions = req.user.permissions || [];
        // Ensure 'read' permission is always present
        if (!currentUserPermissions.includes('read')) {
          currentUserPermissions.push('read');
        }
      }
      return {
        ...lead.toJSON(),
        currentUserPermissions
      };
    });

    res.json({
      success: true,
      count: updatedLeads.length,
      data: updatedLeads
    });
  } catch (err) {
    next(err);
  }
}

// ############################ GET SINGLE LEAD ############################

export async function getBuilding(req, res, next) {
  try {
    const lead = await BuildingInfo.findById(req.params.id)
      .populate('owner', 'firstName lastName')
      .populate('assignedUsers.user', 'firstName lastName email');

    if (!lead) {
      return res.status(404).json({ message: 'Lead not found' });
    }

    const userId = req.user.id;
    const isSameUser = (a) =>
      a?.user && a.user._id && a.user._id.toString() === userId;

    // ================= ACCESS CONTROL =================
    if (req.user.role === 'user') {
      const isOwner = lead.owner?.toString() === userId;
      const assigned = lead.assignedUsers.find(isSameUser);

      if (!isOwner && !assigned) {
        return res.status(403).json({ message: 'No access to this lead' });
      }
    }

    // ================= PERMISSIONS =================
    let currentUserPermissions = [];
    if (req.user.role === 'admin' || req.user.role === 'superadmin') {
      currentUserPermissions = ['read', 'edit', 'delete'];
    } else {
      const isOwner = lead.owner?.toString() === userId;
      const assigned = lead.assignedUsers.find(isSameUser);
      if (isOwner) {
        currentUserPermissions = ['read', 'edit', 'delete'];
      } else if (assigned) {
        currentUserPermissions = assigned.permissions || [];
      }
    }
    res.json({
      success: true,
      data: {
        ...lead.toJSON(),
        currentUserPermissions
      }
    });
  } catch (err) {
    console.error('GET BUILDING ERROR:', err);
    next(err);
  }
}
// ############################ UPDATE LEAD ############################
export async function updateBuilding(req, res, next) {
  try {
    const building = await BuildingInfo.findById(req.params.id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    if (req.user.role === 'admin') {
      // Admin - handled by allowRoles at route level
    } else if (req.user.role !== 'superadmin') {
      // Non-admin users: check edit permission via permissions object
      const assigned = building.assignedUsers.find(
        (a) => a.user.toString() === req.user.id
      );

      if (!assigned || !assigned.permissions.includes('edit')) {
        return res.status(403).json({ message: 'You do not have edit permission' });
      }
    }
    Object.assign(building, req.body);
    // Mixed fields need explicit markModified for nested changes
    if (req.body.attributes) building.markModified('attributes');
    if (req.body.estimatorData) building.markModified('estimatorData');
    if (req.body.userInfo) building.markModified('userInfo');

    if (!building.activities) building.activities = [];
    building.activities.push({
      user: req.user.id,
      action: 'updated',
      details: 'Lead updated'
    });

    await building.save();
    res.json({ success: true, data: building });
  } catch (err) {
    next(err);
  }
}

// ############################ DELETE LEAD ############################
export async function deleteBuilding(req, res, next) {
  try {
    const building = await BuildingInfo.findById(req.params.id);
    if (!building) {
      return res.status(404).json({ message: 'Building not found' });
    }
    if (req.user.role === 'admin') {
      // Admin delete handled by allowRoles at route level (only admins/superadmins reach here)
    } else if (req.user.role !== 'superadmin') {
      // Non-admin users: check delete permission via permissions object
      const assigned = building.assignedUsers.find(
        (a) => a.user.toString() === req.user.id
      );

      if (!assigned || !assigned.permissions.includes('delete')) {
        return res.status(403).json({
          message: 'You do not have delete permission'
        });
      }
    }

    const managedByAdmin = building.managedByAdmin;
    await building.deleteOne();

    // Hard delete removed the doc -> keep the admin's counter in sync (never below 0).
    if (managedByAdmin) await Admin.decrementTotalLeads(managedByAdmin);

    res.json({
      success: true,
      message: 'Building deleted successfully'
    });

  } catch (err) {
    console.error('DELETE BUILDING ERROR:', err);
    next(err);
  }
}

// ############################ ASSIGN USERS ############################
export const assignUsersToBuilding = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { users } = req.body;

    if (!users || !Array.isArray(users)) {
      return res.status(400).json({ message: 'Users array required' });
    }

    const building = await BuildingInfo.findById(id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    if (req.user.role !== 'admin' && req.user.role !== 'superadmin' && req.user.role !== 'delegated') {
      return res.status(403).json({ message: 'Not allowed' });
    }

    if (users.length === 0) {
      building.assignedUsers = [];
      await building.save();
      return res.json({ success: true, data: building });
    }

    const userIds = users.map(u => u.userId);
    const existingUsers = await User.find({ _id: { $in: userIds } });

    if (existingUsers.length !== userIds.length) {
      return res.status(400).json({ message: 'Invalid user IDs provided' });
    }

    building.assignedUsers = users.map(u => ({
      user: u.userId,
      permissions: normalizePermissions(
        u.permissions?.length ? u.permissions : ['read', 'edit', 'delete']
      )
    }));

    await building.save();

    // Trigger in-app notifications for each assigned user
    const leadName = building.userInfo?.firstName
      ? `${building.userInfo.firstName} ${building.userInfo.lastName || ''}`.trim()
      : 'Lead';
    users.forEach(u => {
      notificationService.notifyLeadAssignment({
        lead: building,
        userId: u.userId,
        leadName
      }).catch(err => console.error('Assignment notification error:', err));
    });

    res.json({ success: true, data: building });
  } catch (err) {
    console.error('assignUsersToBuilding error:', err);
    next(err);
  }
};

// ############################ UPDATE USER PERMISSION ############################
export const updateUserPermission = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { userId, permissions } = req.body;

    const building = await BuildingInfo.findById(id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    const assignedUser = getAssignedUser(building, userId);
    if (!assignedUser) return res.status(404).json({ message: 'User not assigned to this lead' });
    assignedUser.permissions = normalizePermissions(permissions);

    await building.save();
    res.json({ success: true, data: building });
  } catch (err) {
    next(err);
  }
};

// ############################ BULK DISTRIBUTE LEADS ############################
export const distributeLeads = async (req, res, next) => {
  try {
    const { userIds } = req.body;
    if (!userIds || !userIds.length) {
      return res.status(400).json({ message: 'userIds required' });
    }

    const buildings = await BuildingInfo.find({ managedByAdmin: req.user.id });
    if (!buildings.length) {
      return res.status(404).json({ message: 'No leads found' });
    }

    const savePromises = buildings.map((building, index) => {
      const userId = userIds[index % userIds.length];
      building.assignedUsers = [
        {
          user: userId,
          permissions: normalizePermissions(['edit', 'delete'])
        }
      ];
      return building.save();
    });

    await Promise.all(savePromises);

    // =============== NOTIFICATIONS ===============
    // Notify users about their new leads (distributed)
    buildings.forEach(building => {
      const assignedUserId = building.assignedUsers[0]?.user;
      if (assignedUserId) {
        User.findById(assignedUserId).then(user => {
          if (user) notificationService.notifyNewLead(user, building);
        }).catch(err => console.error('Notification error in distribution:', err));
      }
    });
    // =============================================

    res.json({ success: true, message: 'Leads distributed successfully' });
  } catch (err) {
    next(err);
  }
};

// ############################ REMOVE ASSIGNED USER ############################
export const removeAssignedUser = async (req, res, next) => {
  try {
    const { id, userId } = req.params;

    const building = await BuildingInfo.findById(id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    building.assignedUsers = building.assignedUsers.filter(
      u => u.user.toString() !== req.user.id
    );

    await building.save();

    res.json({ success: true, data: building });
  } catch (err) {
    next(err);
  }
};

// ############################ UPDATE STATUS ############################
export const updateStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const building = await BuildingInfo.findById(id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    building.status = status;
    await building.save();

    res.json({ success: true, data: building });
  } catch (err) {
    next(err);
  }
};
