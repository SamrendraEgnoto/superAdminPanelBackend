import User from '../models/User.js';
import Admin from '../models/Admin.js';
import BuildingInfo from '../models/BuildingInfo.js';
import mongoose from 'mongoose';
import { hashEmail } from '../utils/encryption.js';
import { ensureTenantDEK } from '../services/tenantCrypto.js';
import { checkEmailExistsAcrossAllRoles } from '../utils/accountUniqueness.js';
import notificationService from '../utils/notificationService.js';

const VALID_PERMISSIONS = ['read', 'edit', 'delete'];

const normalizePermissions = (perms = []) => {
  const filtered = perms.filter(p => VALID_PERMISSIONS.includes(p));
  if (!filtered.includes('read')) filtered.push('read');
  return [...new Set(filtered)];
};

// Profile Management
export async function getProfile(req, res, next) {
  try {
    const user = await User.findById(req.user.id)
      .populate('adminId', 'firstName lastName companyName')
      .populate({ path: 'parentUser', select: 'firstName lastName', strictPopulate: false })
      .select('-password');
    
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Warm tenant DEK so getters / toJSON can decrypt PII
    const tenantId = (user.adminId?._id || user.adminId || user.createdBy?._id || user.createdBy || '').toString();
    if (tenantId) await ensureTenantDEK(tenantId).catch(() => null);

    res.json({ success: true, data: user });
  } catch (err) { 
    next(err); 
  }
}

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
    
    // Prevent updating sensitive fields
    delete updates.password;
    delete updates.role;
    delete updates.adminId;
    delete updates.createdBy;
    
    updates.updatedAt = Date.now();
    
    const user = await User.findByIdAndUpdate(req.user.id, updates, { new: true }).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    res.json({ success: true, data: user });
  } catch (err) { 
    next(err); 
  }
}

export async function getDashboard(req, res, next) {
  try {
    const userId = req.user.id;
    
    const [totalLeads, activeLeads, wonLeads, teamSize, recentLeads] = await Promise.all([
      BuildingInfo.countDocuments({ 
        $or: [{ owner: userId }, { 'assignedUsers.user': userId }] 
      }),
      BuildingInfo.countDocuments({ 
        $or: [{ owner: userId }, { 'assignedUsers.user': userId }],
        status: { $nin: ['closed-won', 'closed-lost'] }
      }),
      BuildingInfo.countDocuments({ 
        owner: userId, 
        status: 'closed-won' 
      }),
      User.countDocuments({ createdBy: userId }),
      BuildingInfo.find({ 
        $or: [{ owner: userId }, { 'assignedUsers.user': userId }] 
      })
        .sort({ updatedAt: -1 })
        .limit(5)
        .select('buildingType userInfo.firstName userInfo.lastName status updatedAt')
        .populate('owner', 'firstName lastName')
    ]);
    
    res.json({
      success: true,
      data: {
        statistics: { totalLeads, activeLeads, wonLeads, teamSize },
        recentActivities: recentLeads
      }
    });
  } catch (err) { 
    next(err); 
  }
}

// Team Management
export async function getTeamMembers(req, res, next) {
  try {
    const parentId = (req.user.adminId || req.user.createdBy || req.user.id || '').toString();
    if (parentId) await ensureTenantDEK(parentId).catch(() => null);

    const teamMembers = await User.find({ createdBy: req.user.id })
      .select('-password')
      .populate('adminId', 'firstName lastName companyName')
      .sort({ createdAt: -1 });
    
    const serialized = teamMembers.map(u => (u.toJSON ? u.toJSON() : u));
    res.json({ success: true, data: serialized });
  } catch (err) { 
    next(err); 
  }
}

export async function createTeamMember(req, res, next) {
  try {
    const currentUser = await User.findById(req.user.id);
    
    if (!currentUser.permissions?.canCreateSubUsers) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to create sub-users' 
      });
    }

    // SaaS Enhancement: Check user limit
    const admin = await Admin.findById(currentUser.adminId);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    const userCount = await User.countDocuments({ adminId: currentUser.adminId });
    if (userCount >= admin.userLimit) {
      return res.status(400).json({ 
        success: false, 
        message: `User limit reached for your plan (${admin.plan}). Current limit: ${admin.userLimit}` 
      });
    }

    const { firstName, lastName, email, password, department, phone } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const normalizedEmail = email.toLowerCase().trim();
    
    // Check if email already exists across ALL roles
    const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (uniqueness.exists) {
      return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
    }

    const newUser = new User({
      firstName,
      lastName,
      email: normalizedEmail,
      password,
      department,
      phone,
      adminId: req.user.adminId,
      createdBy: req.user.id,
      parentUser: req.user.id,
      role: 'user',
      isEmailVerified: true,
      permissions: {
        canCreateLead: false,
        canCreateSubUsers: false,
        canTransferLeads: false,
        canShareLeads: false
      }
    });

    await newUser.save();

    // Warm tenant DEK for response
    if (req.user.adminId) await ensureTenantDEK(req.user.adminId).catch(() => null);

    // Notify new member via email
    try {
      const notificationService = (await import('../utils/notificationService.js')).default;
      await notificationService.notifyUserCreated(newUser, password);
    } catch (notifyErr) {
      console.error('Notification failed but team member was created:', notifyErr.message);
    }
    
    const userResponse = await User.findById(newUser._id)
      .select('-password')
      .populate('adminId', 'firstName lastName companyName');
    
    res.status(201).json({ success: true, data: userResponse });
  } catch (err) { 
    next(err); 
  }
}

export async function updateTeamMember(req, res, next) {
  try {
    const updates = { ...req.body };
    if (updates.email) {
      const normalizedEmail = updates.email.toLowerCase().trim();
      const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail, req.params.id);
      if (uniqueness.exists) {
        return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
      }
      updates.email = normalizedEmail;
    }
    
    // Prevent updating sensitive fields
    delete updates.password;
    delete updates.role;
    delete updates.adminId;
    delete updates.createdBy;
    
    updates.updatedAt = Date.now();
    
    const user = await User.findOneAndUpdate(
      { _id: req.params.id },
      updates,
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found or unauthorized' });
    }
    
    res.json({ success: true, data: user });
  } catch (err) { 
    next(err); 
  }
}

export async function deleteTeamMember(req, res, next) {
  try {
    const user = await User.findOneAndDelete({ _id: req.params.id });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found or unauthorized' });
    }
    
    // Transfer their leads to the manager
    await BuildingInfo.updateMany(
      { owner: req.params.id },
      { owner: req.user.id }
    );
    
    res.json({ success: true, message: 'User deleted and leads transferred' });
  } catch (err) { 
    next(err); 
  }
}

// Building/Lead Management
export async function listMyBuildings(req, res, next) {
  try {
    const { status, priority, page = 1, limit = 10 } = req.query;
    
    let filter = { 
      $or: [
        { owner: req.user.id },
        { 'assignedUsers.user': req.user.id }
      ]
    };
    
    if (status) filter.status = status;
    if (priority) filter.priority = priority;
    
    const skip = (page - 1) * limit;
    
    const buildings = await BuildingInfo.find(filter)
      .populate('owner', 'firstName lastName')
      .populate('assignedUsers.user', 'firstName lastName')
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await BuildingInfo.countDocuments(filter);
    
    // Warm tenant DEKs so toJSON / getters can decrypt PII
    const tenantIds = [
      ...new Set(
        buildings.map(b => (b.managedByAdmin || b.managedBySuperAdmin || '').toString()).filter(Boolean)
      )
    ];
    if (req.user.adminId) tenantIds.push(req.user.adminId.toString());
    if (req.user.createdBy) tenantIds.push(req.user.createdBy.toString());
    await Promise.all(tenantIds.map(tid => ensureTenantDEK(tid).catch(() => null)));

    res.json({
      success: true,
      data: buildings.map(b => (typeof b.toJSON === 'function' ? b.toJSON() : b)),
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalItems: total
      }
    });
  } catch (err) { 
    next(err); 
  }
}

export async function getMyBuilding(req, res, next) {
  try {
    const building = await BuildingInfo.findOne({ 
      _id: req.params.id,
      $or: [
        { owner: req.user.id },
        { 'assignedUsers.user': req.user.id }
      ]
    })
      .populate('owner', 'firstName lastName')
      .populate('assignedUsers.user', 'firstName lastName')
      .populate('transferHistory.fromUser', 'firstName lastName')
      .populate('transferHistory.toUser', 'firstName lastName');
    
    if (!building) return res.status(404).json({ message: 'Building not found' });
    
    const tenantId = (building.managedByAdmin || building.managedBySuperAdmin || req.user.adminId || req.user.createdBy || '').toString();
    if (tenantId) await ensureTenantDEK(tenantId).catch(() => null);

    res.json({ success: true, data: typeof building.toJSON === 'function' ? building.toJSON() : building });
  } catch (err) { 
    next(err); 
  }
}

export async function createMyBuilding(req, res, next) {
  try {
    if (!req.user.canCreateLead) {
      return res.status(403).json({ 
        success: false, 
        message: 'You do not have permission to create leads' 
      });
    }

    const owningAdmin = await Admin.findById(req.user.adminId).select('createdBy');

    const buildingData = { 
      ...req.body, 
      owner: ['admin', 'superadmin'].includes(req.user.role) ? null : req.user.id,
      managedByAdmin: req.user.adminId,
      managedBySuperAdmin: owningAdmin?.createdBy || null,
      activities: [{
        user: req.user.id,
        action: 'created',
        details: 'Lead created'
      }]
    };
    
    const building = new BuildingInfo(buildingData);
    await building.save();
    
    // Keep the owning admin's lead counter in sync (atomic $inc).
    if (req.user.adminId) await Admin.incrementTotalLeads(req.user.adminId);
    
    // Update user's lead count
    await User.findByIdAndUpdate(req.user.id, { 
      $inc: { leadsAssigned: 1 } 
    });
    
    const populatedBuilding = await BuildingInfo.findById(building._id)
      .populate('owner', 'firstName lastName');
    
    const tenantId = (building.managedByAdmin || building.managedBySuperAdmin || req.user.adminId || req.user.createdBy || '').toString();
    if (tenantId) await ensureTenantDEK(tenantId).catch(() => null);

    res.status(201).json({ success: true, data: typeof populatedBuilding.toJSON === 'function' ? populatedBuilding.toJSON() : populatedBuilding });
  } catch (err) { 
    next(err); 
  }
}

export async function updateMyBuilding(req, res, next) {
  try {
    const updates = { ...req.body, updatedAt: Date.now() };
    
    // First find the building to check permissions
    const building = await BuildingInfo.findById(req.params.id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    const assigned = building.assignedUsers.find(a => a.user.toString() === req.user.id);
    
    if (!assigned || !assigned.permissions.includes('edit')) {
      return res.status(403).json({ message: 'No edit permission' });
    }

    const updatedBuilding = await BuildingInfo.findByIdAndUpdate(
      req.params.id, 
      {
        ...updates,
        $push: {
          activities: {
            user: req.user.id,
            action: 'updated',
            details: `Updated: ${Object.keys(req.body).join(', ')}`
          }
        }
      }, 
      { new: true }
    ).populate('owner', 'firstName lastName');
    
    if (!updatedBuilding) {
      return res.status(404).json({ message: 'Building not found or not authorized' });
    }

    const tenantId = (updatedBuilding.managedByAdmin || updatedBuilding.managedBySuperAdmin || req.user.adminId || req.user.createdBy || '').toString();
    if (tenantId) await ensureTenantDEK(tenantId).catch(() => null);
    
    res.json({ success: true, data: typeof updatedBuilding.toJSON === 'function' ? updatedBuilding.toJSON() : updatedBuilding });
  } catch (err) { 
    next(err); 
  }
}

export async function deleteMyBuilding(req, res, next) {
  try {
    const building = await BuildingInfo.findById(req.params.id);
    if (!building) return res.status(404).json({ message: 'Building not found' });

    const assigned = building.assignedUsers.find(a => a.user.toString() === req.user.id);
    
    if (!assigned || !assigned.permissions.includes('delete')) {
      return res.status(403).json({ message: 'No delete permission' });
    }

    const removed = await BuildingInfo.findByIdAndDelete(req.params.id);

    // Hard delete removed the doc -> keep the owning admin's counter in sync (never below 0).
    if (removed && removed.managedByAdmin) await Admin.decrementTotalLeads(removed.managedByAdmin);
    
    if (!building) {
      return res.status(404).json({ message: 'Building not found or not authorized' });
    }
    
    res.json({ success: true, message: 'Building deleted' });
  } catch (err) { 
    next(err); 
  }
}

// Lead Transfer
export async function transferLead(req, res, next) {
  try {
    const { targetUserId, transferType = 'full', reason } = req.body;
    
    const building = await BuildingInfo.findOne({ _id: req.params.id });
    
    if (!building) {
      return res.status(404).json({ message: 'Lead not found or not authorized' });
    }

    // Verify target user exists and belongs to same admin
    const targetUser = await User.findOne({ 
      _id: targetUserId, 
      adminId: building.managedByAdmin 
    });
    
    if (!targetUser) {
      return res.status(400).json({ message: 'Target user not found or not in same organization' });
    }

    if (transferType === 'full') {
      building.owner = targetUserId;
      // Update lead counts
      await User.findByIdAndUpdate(req.user.id, { $inc: { leadsAssigned: -1 } });
      await User.findByIdAndUpdate(targetUserId, { $inc: { leadsAssigned: 1 } });
    } else if (transferType === 'shared') {
      if (!building.assignedUsers.some(a => a.user.toString() === targetUserId)) {
        building.assignedUsers.push({
          user: targetUserId,
          permissions: ['read'] // Default to read
        });
      }
    }

    // Add to transfer history
    building.transferHistory.push({
      fromUser: req.user.id,
      toUser: targetUserId,
      transferType,
      reason
    });
    
    building.activities.push({
      user: req.user.id,
      action: transferType === 'full' ? 'transferred' : 'shared',
      details: `Lead ${transferType === 'full' ? 'transferred to' : 'shared with'} ${targetUser.firstName} ${targetUser.lastName}`
    });

    await building.save();
    
    const updatedBuilding = await BuildingInfo.findById(building._id)
      .populate('owner', 'firstName lastName')
      .populate('assignedUsers.user', 'firstName lastName');
    
    res.json({ success: true, data: updatedBuilding });
  } catch (err) { 
    next(err); 
  }
}
export const getAllUsers = async (req, res, next) => {
  try {
    const adminId = new mongoose.Types.ObjectId(req.user.id);

    // Warm tenant DEK so getters/toJSON decrypt PII
    await ensureTenantDEK(req.user.id).catch(() => null);

    const users = await User.find({ adminId }).select('-password').sort({ createdAt: -1 });

    // ================= UNIQUE LEADS PER USER =================
    const leadStats = await BuildingInfo.aggregate([
      {
        $match: {
          managedByAdmin: adminId
        }
      },
      {
        $project: {
          users: {
            $setUnion: [
              [{ $toString: "$owner" }],
              {
                $map: {
                  input: "$assignedUsers",
                  as: "a",
                  in: { $toString: "$$a.user" }
                }
              }
            ]
          },
          status: 1
        }
      },
      { $unwind: "$users" },
      {
        $group: {
          _id: "$users",
          leadCount: { $sum: 1 },
          wonLeads: {
            $sum: {
              $cond: [{ $eq: ["$status", "closed-won"] }, 1, 0]
            }
          }
        }
      }
    ]);

    // ================= MAP =================
    const statsMap = {};
    leadStats.forEach(s => {
      statsMap[s._id] = s;
    });

    // ================= FINAL USERS =================
    const usersWithStats = users.map(user => {
      const stats = statsMap[user._id.toString()] || {};

      return {
        ...user.toJSON(),
        statistics: {
          leadCount: stats.leadCount || 0,
          wonLeads: stats.wonLeads || 0
        }
      };
    });

    res.json({
      success: true,
      data: usersWithStats
    });

  } catch (err) {
    console.error('getAllUsers error:', err);
    next(err);
  }
};

export const createUser = async (req, res, next) => {
  try {
    // SaaS Enhancement: Check user limit
    const adminId = req.user.adminId;
    const admin = await Admin.findById(adminId);
    if (!admin) return res.status(404).json({ message: 'Admin not found' });

    const userCount = await User.countDocuments({ adminId });
    if (userCount >= admin.userLimit) {
      return res.status(400).json({ 
        success: false, 
        message: `User limit reached for your plan (${admin.plan}). Current limit: ${admin.userLimit}` 
      });
    }

    const { firstName, lastName, email, password, designation } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user exists across ALL roles
    const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (uniqueness.exists) {
      return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
    }

    const newUser = new User({
      firstName,
      lastName,
      email: normalizedEmail,
      password,
      role: 'user',
      designation,
      adminId: req.user.adminId,
      // Admin/superadmin-created users are auto-verified: the business owner
      // vouches for them, so they can log in immediately without OTP.
      isEmailVerified: true,
    });

    await newUser.save();

    // Warm tenant DEK for response
    if (adminId) await ensureTenantDEK(adminId).catch(() => null);

    // Notify new user via email and in-app for creator
    try {
      await notificationService.notifyUserCreated(newUser, password);
      await notificationService.notifyUserCreatedEvent({ 
        user: newUser, 
        creatorId: req.user.id 
      });
    } catch (notifyErr) {
      console.error('Notification failed but user was created:', notifyErr.message);
    }

    const userResponse = await User.findById(newUser._id).select('-password');

    res.status(201).json({
      success: true,
      data: userResponse ? userResponse.toJSON() : newUser.toJSON()
    });
  } catch (err) {
    next(err);
  }
};

// ############################ ASSIGN LEADS TO USER ############################


export const assignLeadsToUser = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { leads } = req.body;

    // Allow empty array (important)
    if (!Array.isArray(leads)) {
      return res.status(400).json({ message: 'Leads array required' });
    }

    const selectedLeadIds = leads.map(l => l.leadId.toString());

    // ================= GET ALL LEADS UNDER CALLER =================
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
      // Admin (Tenant or Data-Viewer)
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

          // Trigger in-app notification for the user
          const leadName = building.userInfo?.firstName
            ? `${building.userInfo.firstName} ${building.userInfo.lastName || ''}`.trim()
            : (building.customerName || building.name || 'Lead');
          notificationService.notifyLeadAssignment({
            lead: building,
            userId,
            leadName
          }).catch(err => console.error('Assignment notification error:', err));
        }
      } else {
        // ❗ REMOVE USER FROM UNSELECTED LEADS
        if (existingIndex !== -1) {
          building.assignedUsers.splice(existingIndex, 1);
        }
      }

      await building.save();
    }

    return res.json({
      success: true,
      message: 'Leads assigned successfully'
    });

  } catch (err) {
    console.error('assignLeadsToUser error:', err);
    next(err);
  }
};

