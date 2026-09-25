import mongoose from 'mongoose';
import Admin from '../models/Admin.js';
import User from '../models/User.js';
import BuildingInfo from '../models/BuildingInfo.js';
import SuperAdmin from '../models/SuperAdmin.js';

export const getReports = async (req, res, next) => {
  try {
    const { role, id, adminId } = req.user;
    let stats = {
      totalLeads: 0,
      convertedLeads: 0,
      revenue: 0,
      activeUsers: 0
    };
    let metrics = {
      conversionRate: { value: '0%', change: '0%', trend: 'neutral' },
      avgDealSize: { value: '$0', change: '0%', trend: 'neutral' },
      responseTime: { value: '0h', change: '0h', trend: 'neutral' },
      satisfaction: { value: '0/5', change: '0', trend: 'neutral' }
    };

    if (role === 'superadmin') {
      if (req.user.dbRole === 'delegated') {
        let dsaObjId = null;
        try {
          if (mongoose.Types.ObjectId.isValid(id)) dsaObjId = new mongoose.Types.ObjectId(id);
        } catch (e) {}

        const dsaAdminList = await Admin.find({
          $or: [
            { createdById: id },
            { createdBy: id },
            ...(dsaObjId ? [{ createdById: dsaObjId }, { createdBy: dsaObjId }] : [])
          ]
        }).select('_id isActive').lean();
        const adminIds = dsaAdminList.map(a => a._id);
        const activeAdmins = dsaAdminList.filter(a => a.isActive).length;

        const leadFilter = {
          $or: [
            { managedBySuperAdmin: id },
            ...(dsaObjId ? [{ managedBySuperAdmin: dsaObjId }] : []),
            ...(adminIds.length > 0 ? [{ managedByAdmin: { $in: adminIds } }] : [])
          ]
        };

        const [totalLeads, convertedLeads] = await Promise.all([
          BuildingInfo.countDocuments(leadFilter),
          BuildingInfo.countDocuments({
            ...leadFilter,
            status: { $in: ['closed-won', 'won', 'closed', 'converted'] }
          })
        ]);

        stats.activeUsers = activeAdmins;
        stats.totalLeads = totalLeads;
        stats.convertedLeads = convertedLeads;
      } else {
        const [activeUsers, totalLeads, convertedLeads] = await Promise.all([
          Admin.countDocuments({ isActive: true }),
          BuildingInfo.countDocuments(),
          BuildingInfo.countDocuments({ status: { $in: ['closed-won', 'won', 'closed', 'converted'] } })
        ]);
        stats.activeUsers = activeUsers;
        stats.totalLeads = totalLeads;
        stats.convertedLeads = convertedLeads;
      }
    } else if (role === 'admin') {
      const [activeUsers, totalLeads, convertedLeads] = await Promise.all([
        User.countDocuments({ adminId: id, isActive: true }),
        BuildingInfo.countDocuments({ managedByAdmin: id }),
        BuildingInfo.countDocuments({ managedByAdmin: id, status: 'closed-won' })
      ]);
      stats.activeUsers = activeUsers;
      stats.totalLeads = totalLeads;
      stats.convertedLeads = convertedLeads;
    } else {
      const [totalLeads, convertedLeads] = await Promise.all([
        BuildingInfo.countDocuments({ 
          $or: [{ owner: id }, { 'assignedUsers.user': id }] 
        }),
        BuildingInfo.countDocuments({ 
          owner: id, 
          status: 'closed-won' 
        })
      ]);
      stats.totalLeads = totalLeads;
      stats.convertedLeads = convertedLeads;
    }

    // Simplified metrics for now
    if (stats.totalLeads > 0) {
      const rate = Math.round((stats.convertedLeads / stats.totalLeads) * 100);
      metrics.conversionRate.value = `${rate}%`;
      metrics.conversionRate.trend = rate > 50 ? 'positive' : 'neutral';
    }

    res.json({
      success: true,
      stats,
      metrics
    });
  } catch (err) {
    next(err);
  }
};

export const exportReport = async (req, res, next) => {
  // For now, we'll return a simple response. 
  // Real implementation would use jspdf on frontend as suggested in implementation plan.
  // But since existing frontend expects a blob, we'll implement a placeholder.
  res.status(200).json({ message: "PDF export logic should be handled by the frontend for this implementation." });
};
