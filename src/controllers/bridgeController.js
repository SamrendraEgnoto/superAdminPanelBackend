import mongoose from 'mongoose';
import BuildingInfo from '../models/BuildingInfo.js';
import Admin from '../models/Admin.js';
import SuperAdmin from '../models/SuperAdmin.js';
import notificationService from '../utils/notificationService.js';
import AuditLog from '../models/AuditLog.js';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { buildCustomerRightsLink } from '../utils/customerToken.js';
import { resolveEmbedKey } from '../middlewares/embedKeyAuth.js';

// Shared service credential for bridge authentication
// Both Super Admin Panel and Estimator_Node must configure the same value
const SHARED_API_KEY = process.env.BRIDGE_API_KEY || 'bridge-shared-key-secret';

/**
 * Validate service-to-service bridge request credentials (X-API-Key header).
 * Returns true when the shared key matches; otherwise writes a 401 and returns
 * false. NOT an express middleware (it must not call next()) because it is
 * invoked from inside the route handler — calling next() would fall through and
 * let express answer a default 404 for a matched route.
 */
const authenticateBridgeRequest = (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== SHARED_API_KEY) {
    console.warn(`[Bridge Auth] Invalid API key attempt: ${apiKey}`);
    res.status(401).json({ message: 'Unauthorized: Invalid service credentials' });
    return false;
  }
  return true;
};

/**
 * Log a bridge call into the audit database
 */
const logBridgeCall = async (direction, endpoint, status, error = null, details = {}, req = null) => {
  try {
    let actorId, actorRole;
    
    // Determine actor based on direction
    if (direction === 'en-to-sa') {
      // Inbound from Estimator_Node - use the admin who received the lead
      actorId = details?.adminId;
      actorRole = 'admin';
    } else {
      // Outbound to Estimator_Node - use the current super admin
      actorId = req?.user?.id;
      actorRole = req?.user?.role || 'system';
    }
    
    const logEntry = new AuditLog({
      actorId,
      actorRole,
      action: `bridge_${direction}_${status}`,
      actionCategory: 'internal_api',
      targetType: 'bridge_call',
      targetId: details?.adminId || details?.leadId,
      tenantAdminId: details?.adminId,
      metadata: new Map([
        ['endpoint', endpoint],
        ['direction', direction],
        ['status', status],
        ...(error ? [['error', error.message]] : [])
      ]),
      ipAddress: req?.ip || req?.headers['x-forwarded-for'] || 'unknown',
    });
    await logEntry.save();
  } catch (err) {
    console.error(`[Bridge Audit] Failed to log call:`, err.message);
  }
};

/**
 * @brief Receive lead submissions from Estimator_Node
 * @route POST /api/bridge/leads
 * @access Authenticated (service-to-service via JWT)
 * 
 * Body: { tenantId, customer: {...}, buildingType, estimatorBuildingId }
 * 
 * Idempotent on estimatorBuildingId — a retried submission must not create a duplicate lead.
 * Looks up Admin directly by _id: tenantId (no separate lookup table needed).
 * Creates BuildingInfo record with: managedByAdminId: tenantId, source: 'website',
 * estimatorBuildingId stored as reference only, status: 'new'.
 */
export async function submitLeadFromEstimator(req, res, next) {
  try {
    if (!authenticateBridgeRequest(req, res)) return;
    
    const {
      tenantId,
      customer,
      buildingType,
      estimatorBuildingId,
      consentGiven,
      consentTimestamp,
      consentTextVersion
    } = req.body;

    if (!tenantId || !estimatorBuildingId) {
      return res.status(400).json({ message: 'tenantId and estimatorBuildingId are required' });
    }

    // 1. Idempotency check: if same estimatorBuildingId already exists, return existing lead
    const existingLead = await BuildingInfo.findOne({ estimatorBuildingId });
    if (existingLead) {
      // Log idempotent return
      await logBridgeCall('en-to-sa', '/bridge/leads', 'idempotent', null, {
        adminId: tenantId,
        leadId: existingLead._id
      }, req);
      console.log(`[Bridge] Duplicate estimatorBuildingId detected: ${estimatorBuildingId}. Returning existing lead ${existingLead._id}.`);
      return res.json({ 
        success: true, 
        data: { leadId: existingLead._id, ...buildCustomerRightsLink(existingLead._id) },
        message: 'Lead already submitted (idempotent)' 
      });
    }

    // 2. Look up the Admin or SuperAdmin directly by tenantId (ObjectId or Embed Key)
    let admin = null;
    let superAdmin = null;
    if (tenantId && mongoose.Types.ObjectId.isValid(tenantId)) {
      admin = await Admin.findById(tenantId);
      if (!admin) {
        superAdmin = await SuperAdmin.findById(tenantId);
      }
    }
    if (!admin && !superAdmin && tenantId) {
      const resolved = await resolveEmbedKey(tenantId);
      if (resolved && resolved.valid) {
        if (resolved.adminId) admin = await Admin.findById(resolved.adminId);
        if (resolved.superAdminId && (!admin || resolved.isSuperAdmin)) {
          superAdmin = await SuperAdmin.findById(resolved.superAdminId);
        }
      }
    }
    if (!admin && !superAdmin) {
      // Log failed lookup
      await logBridgeCall('en-to-sa', '/bridge/leads', 'admin_not_found', new Error('Tenant not found'), {
        tenantId,
        leadId: null
      }, req);
      return res.status(404).json({ message: 'Tenant not found for given tenantId' });
    }

    // 3. Prepare userInfo for BuildingInfo from customer data
    const rawCustomer = customer || req.body.userInfo || {};
    const userInfo = {
      firstName: rawCustomer.firstName || '',
      lastName: rawCustomer.lastName || '',
      email: rawCustomer.email || '',
      phoneNumber: rawCustomer.phoneNumber || rawCustomer.phone || '',
      phone: rawCustomer.phone || rawCustomer.phoneNumber || '',
      address: rawCustomer.address || '',
      city: rawCustomer.city || '',
      state: rawCustomer.state || '',
      zip: rawCustomer.zip || '',
      notes: rawCustomer.notes || ''
    };

    // 4. Create BuildingInfo record under this Admin / SuperAdmin
    const managedByAdmin = admin ? admin._id : null;
    const managedBySuperAdmin = superAdmin ? superAdmin._id : (admin?.createdById || admin?.createdBy || null);

    const newLead = new BuildingInfo({
      buildingType: buildingType || 'unknown',
      userInfo,
      source: 'website',
      managedByAdmin: managedByAdmin || undefined,
      managedBySuperAdmin: managedBySuperAdmin || undefined,
      estimatorBuildingId, // store the reference from Estimator_Node
      status: 'new',
      // Consent captured by the 3D Estimator (GDPR/CCPA); stored verbatim.
      consentGiven: typeof consentGiven === 'boolean' ? consentGiven : undefined,
      consentTimestamp: consentTimestamp ? new Date(consentTimestamp) : undefined,
      consentTextVersion: consentTextVersion ? String(consentTextVersion) : undefined,
      assignedUsers: admin ? [
        {
          user: admin._id,
          permissions: ['read', 'edit', 'delete']
        }
      ] : []
    });

    await newLead.save();

    // Keep the admin's lead counter in sync (atomic $inc, race-safe).
    if (managedByAdmin) await Admin.incrementTotalLeads(managedByAdmin);

    // 5. Trigger in-app + email notification
    try {
      const rawCustomerName = (`${rawCustomer.firstName || ''} ${rawCustomer.lastName || ''}`.trim() || rawCustomer.name || rawCustomer.email || '').trim();
      await notificationService.notifyLeadArrival(newLead, { admin, superAdmin, rawCustomerName });
      console.log(`[Bridge] In-app & email notification triggered for new lead ${newLead._id}`);
    } catch (notifyErr) {
      console.error(`[Bridge] Failed to send lead notification:`, notifyErr.message);
      // Don't fail the lead creation if notification fails
    }

    // Log successful inbound bridge call
    await logBridgeCall('en-to-sa', '/bridge/leads', 'success', null, {
      adminId: managedByAdmin || managedBySuperAdmin,
      leadId: newLead._id
    }, req);
    
    console.log(`[Bridge] New lead created: ${newLead._id}, estimatorBuildingId: ${estimatorBuildingId}`);

    res.status(201).json({ 
      success: true, 
      data: { leadId: newLead._id, ...buildCustomerRightsLink(newLead._id) },
      message: 'Lead submitted and recorded successfully' 
    });
  } catch (err) {
    next(err);
  }
}

/**
 * @desc Create a lead authenticated by an embed key (no JWT).
 * @route POST /api/bridge/embed/leads
 * @access Embed key (scope: create-lead-only)
 * Resolves the owning admin via embedKeyAuth (req.adminId), enforces scope,
 * and creates a BuildingInfo lead under that admin. Idempotent by
 * estimatorBuildingId.
 */
export async function submitLeadFromEmbed(req, res, next) {
  try {
    if (!req.adminId && !req.superAdminId) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }

    const scope = req.embedKeyScope || 'create-lead-only';
    if (scope !== 'create-lead-only') {
      return res.status(403).json({ success: false, message: 'Embed key scope does not allow lead creation' });
    }

    const { buildingType, customer, estimatorBuildingId, consentGiven, consentTimestamp, consentTextVersion } = req.body || {};

    if (estimatorBuildingId) {
      const existing = await BuildingInfo.findOne({ estimatorBuildingId });
      if (existing) {
        return res.json({ success: true, data: { leadId: existing._id, ...buildCustomerRightsLink(existing._id) }, message: 'Lead already exists (idempotent)' });
      }
    }

    const rawCustomer = customer || req.body.userInfo || {};
    const userInfo = {
      firstName: rawCustomer.firstName || '',
      lastName: rawCustomer.lastName || '',
      email: rawCustomer.email || '',
      phoneNumber: rawCustomer.phoneNumber || rawCustomer.phone || '',
      phone: rawCustomer.phone || rawCustomer.phoneNumber || '',
      address: rawCustomer.address || '',
      city: rawCustomer.city || '',
      state: rawCustomer.state || '',
      zip: rawCustomer.zip || '',
      notes: rawCustomer.notes || ''
    };

    let managedBySuperAdmin = req.superAdminId || undefined;
    if (!managedBySuperAdmin && req.adminId) {
      const owning = await Admin.findById(req.adminId).select('createdById createdBy');
      managedBySuperAdmin = owning?.createdById || owning?.createdBy || undefined;
    }

    const lead = new BuildingInfo({
      buildingType: buildingType || 'unknown',
      userInfo,
      source: 'embed',
      managedByAdmin: req.adminId || undefined,
      managedBySuperAdmin,
      status: 'new',
      estimatorBuildingId: estimatorBuildingId || undefined,
      // Consent captured by the 3D Estimator (GDPR/CCPA); stored verbatim.
      consentGiven: typeof consentGiven === 'boolean' ? consentGiven : undefined,
      consentTimestamp: consentTimestamp ? new Date(consentTimestamp) : undefined,
      consentTextVersion: consentTextVersion ? String(consentTextVersion) : undefined
    });
    await lead.save();

    if (req.adminId) {
      await Admin.incrementTotalLeads(req.adminId);
    }

    // Trigger in-app + email notification for the tenant (RCA or DSA)
    try {
      const rawCustomerName = (`${userInfo.firstName || ''} ${userInfo.lastName || ''}`.trim() || userInfo.email || '').trim();
      await notificationService.notifyLeadArrival(lead, {
        admin: req.adminId || undefined,
        superAdmin: managedBySuperAdmin,
        rawCustomerName
      });
    } catch (notifyErr) {
      console.error('[Embed] Lead arrival notification error:', notifyErr.message);
    }

    res.status(201).json({
      success: true,
      data: { leadId: lead._id, ...buildCustomerRightsLink(lead._id) },
      message: 'Lead created via embed key'
    });
  } catch (err) {
    next(err);
  }
}

