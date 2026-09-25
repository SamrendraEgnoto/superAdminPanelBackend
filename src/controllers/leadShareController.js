/**
 * leadShareController.js
 *
 * Handles all lead sharing logic between Delegated Super Admins (DSA) and
 * their Data-Viewer Admins.
 *
 * Business Rules:
 *  - Only DSAs can share leads (leads they own via managedBySuperAdmin).
 *  - Admins being shared to must be of adminType 'data-viewer' AND must have
 *    been created by the calling DSA (createdById === DSA._id).
 *  - The DSA always retains full ownership and visibility of the lead.
 *  - A shared lead is visible to the data-viewer Admin via the sharedWith[] array.
 *  - Data-viewer Admins can assign shared leads to their Users (no re-sharing).
 */

import BuildingInfo from '../models/BuildingInfo.js';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import AuditLog from '../models/AuditLog.js';
import notificationService from '../utils/notificationService.js';

// ---------------------------------------------------------------------------
// GET /api/superadmin/leads
// DSA fetches all their own leads (from their embed key) with sharing info.
// ---------------------------------------------------------------------------
export async function getDsaLeads(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('role');
    if (!sa || sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Only Delegated Super Admins can access this endpoint.' });
    }

    const { status, page = 1, limit = 50 } = req.query;
    const filter = { managedBySuperAdmin: req.user.id };
    if (status) filter.status = status;

    const skip = (Number(page) - 1) * Number(limit);

    const [leads, total] = await Promise.all([
      BuildingInfo.find(filter)
        .populate('sharedWith.adminId', 'firstName lastName companyName')
        .populate('sharedWith.sharedBy', 'firstName lastName')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean({ virtuals: false }),
      BuildingInfo.countDocuments(filter)
    ]);

    res.json({
      success: true,
      data: leads,
      pagination: { total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / Number(limit)) }
    });
  } catch (err) { next(err); }
}

// ---------------------------------------------------------------------------
// POST /api/superadmin/leads/share
// DSA shares one or more leads to a data-viewer Admin.
// Body: { leadIds: [string, ...], adminId: string, note?: string }
// ---------------------------------------------------------------------------
export async function shareLead(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('role');
    if (!sa || sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Only Delegated Super Admins can share leads.' });
    }

    const { leadIds, adminId, note = '' } = req.body;
    if (!leadIds || !Array.isArray(leadIds) || leadIds.length === 0) {
      return res.status(400).json({ message: 'leadIds must be a non-empty array.' });
    }
    if (!adminId) {
      return res.status(400).json({ message: 'adminId is required.' });
    }

    // Validate that the target Admin is a data-viewer created by this DSA
    const targetAdmin = await Admin.findById(adminId).select('adminType createdById isActive');
    if (!targetAdmin) return res.status(404).json({ message: 'Target Admin not found.' });
    if (targetAdmin.adminType !== 'data-viewer') {
      return res.status(403).json({ message: 'You can only share leads to data-viewer admins.' });
    }
    if (targetAdmin.createdById?.toString() !== req.user.id) {
      return res.status(403).json({ message: 'You can only share to admins you created.' });
    }
    if (!targetAdmin.isActive) {
      return res.status(400).json({ message: 'Target admin is inactive. Activate them before sharing.' });
    }

    const results = { shared: [], alreadyShared: [], notFound: [], notOwned: [] };

    for (const leadId of leadIds) {
      const lead = await BuildingInfo.findById(leadId);
      if (!lead) { results.notFound.push(leadId); continue; }

      if (!lead.managedBySuperAdmin || lead.managedBySuperAdmin.toString() !== req.user.id) {
        results.notOwned.push(leadId);
        continue;
      }

      const alreadyShared = (lead.sharedWith || []).some(s => s.adminId?.toString() === adminId);
      if (alreadyShared) { results.alreadyShared.push(leadId); continue; }

      lead.sharedWith = lead.sharedWith || [];
      lead.sharedWith.push({ adminId, sharedAt: new Date(), sharedBy: req.user.id, note });
      await lead.save();
      results.shared.push(leadId);

      // Trigger notification for shared admin
      const leadName = lead.userInfo?.firstName
        ? `${lead.userInfo.firstName} ${lead.userInfo.lastName || ''}`.trim()
        : 'Lead';
      notificationService.notifyLeadShared({
        lead,
        adminId,
        leadName
      }).catch(err => console.error('Share notification err:', err));
    }

    if (results.shared.length > 0) {
      await AuditLog.create({
        actorId: req.user.id,
        actorRole: req.user.role,
        action: 'lead.share',
        actionCategory: 'lead_mgmt',
        targetType: 'admin',
        targetId: adminId,
        ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
        metadata: { sharedLeadIds: results.shared, sharedToAdminId: adminId, count: results.shared.length, note }
      });
    }

    res.json({
      success: true,
      results,
      summary: {
        requested: leadIds.length,
        shared: results.shared.length,
        alreadyShared: results.alreadyShared.length,
        notFound: results.notFound.length,
        notOwned: results.notOwned.length
      }
    });
  } catch (err) { next(err); }
}

// ---------------------------------------------------------------------------
// DELETE /api/superadmin/leads/:id/share/:adminId
// DSA unshares a specific lead from a specific data-viewer Admin.
// ---------------------------------------------------------------------------
export async function unshareLead(req, res, next) {
  try {
    const sa = await SuperAdmin.findById(req.user.id).select('role');
    if (!sa || sa.role !== 'delegated') {
      return res.status(403).json({ message: 'Only Delegated Super Admins can unshare leads.' });
    }

    const { id: leadId, adminId } = req.params;
    const lead = await BuildingInfo.findById(leadId);
    if (!lead) return res.status(404).json({ message: 'Lead not found.' });

    if (!lead.managedBySuperAdmin || lead.managedBySuperAdmin.toString() !== req.user.id) {
      return res.status(403).json({ message: 'You can only unshare leads you own.' });
    }

    const before = (lead.sharedWith || []).length;
    lead.sharedWith = (lead.sharedWith || []).filter(s => s.adminId?.toString() !== adminId);
    if (before === lead.sharedWith.length) {
      return res.status(404).json({ message: 'This lead was not shared with that admin.' });
    }

    await lead.save();

    await AuditLog.create({
      actorId: req.user.id,
      actorRole: req.user.role,
      action: 'lead.unshare',
      actionCategory: 'lead_mgmt',
      targetType: 'admin',
      targetId: adminId,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      metadata: { leadId, removedFromAdminId: adminId }
    });

    res.json({ success: true, message: 'Lead unshared successfully.' });
  } catch (err) { next(err); }
}

// ---------------------------------------------------------------------------
// GET /api/admin/shared-leads
// Data-viewer Admin fetches only the leads shared with them.
// Called from the Admin panel (auth as Admin, not SuperAdmin).
// ---------------------------------------------------------------------------
export async function getSharedLeads(req, res, next) {
  try {
    const callerAdmin = await Admin.findById(req.user.id).select('adminType');
    if (!callerAdmin || callerAdmin.adminType !== 'data-viewer') {
      return res.status(403).json({
        message: 'This endpoint is for data-viewer admins only.'
      });
    }

    const { status, page = 1, limit = 50 } = req.query;
    const filter = { 'sharedWith.adminId': req.user.id };
    if (status) filter.status = status;

    const skip = (Number(page) - 1) * Number(limit);
    const [leads, total] = await Promise.all([
      BuildingInfo.find(filter)
        .populate('managedBySuperAdmin', 'firstName lastName')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit))
        .lean({ virtuals: false }),
      BuildingInfo.countDocuments(filter)
    ]);

    // Strip sharedWith — data-viewer doesn't need to know about other admins
    const sanitized = leads.map(l => {
      const myShare = (l.sharedWith || []).find(s => s.adminId?.toString() === req.user.id);
      const { sharedWith, ...rest } = l;
      return { ...rest, sharedAt: myShare?.sharedAt, sharedNote: myShare?.note };
    });

    res.json({
      success: true,
      data: sanitized,
      pagination: { total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / Number(limit)) }
    });
  } catch (err) { next(err); }
}
