import BuildingInfo from '../models/BuildingInfo.js';
import Admin from '../models/Admin.js';
import AuditLog from '../models/AuditLog.js';
import { ensureTenantDEK } from '../services/tenantCrypto.js';

// Fields a customer may correct about themselves. Deliberately excludes
// internal fields (status, assignedUsers, managedByAdmin, managedBySuperAdmin,
// owner, estimatorBuildingId, notes, marketingConsent, ...).
const ALLOWED_CUSTOMER_FIELDS = ['firstName', 'lastName', 'email', 'phoneNumber', 'address', 'city', 'state', 'zip'];

const validIpOrUndefined = (ip) =>
  ip && /^(\d{1,3}\.){3}\d{1,3}$|^::1$|^[0-9a-f:]+$/i.test(String(ip)) ? String(ip) : undefined;

// Best-effort: if the tenant DEK happens to be resolvable (passkey already in
// the server session / wrapped blob cached), warm it so decryption works. Falls
// back silently to the legacy master key otherwise.
const warmTenantDEK = async (lead) => {
  if (lead && lead.managedByAdmin) {
    try {
      await ensureTenantDEK(lead.managedByAdmin);
    } catch {
      // best effort only
    }
  }
};

const buildPublicUserInfo = (lead) => ({
  firstName: lead.getFirstName(),
  lastName: lead.getLastName(),
  email: lead.getEmail(),
  phoneNumber: lead.getPhone(),
  address: lead.userInfo && lead.userInfo.address || '',
  city: lead.userInfo && lead.userInfo.city || '',
  state: lead.userInfo && lead.userInfo.state || '',
  zip: lead.userInfo && lead.userInfo.zip || ''
});

// GET /api/customer/:leadId/export?token=<quoteToken>
// Returns the customer's own lead data (decrypted), scoped by the token.
export async function getCustomerLead(req, res, next) {
  try {
    const lead = await BuildingInfo.findById(req.params.leadId);
    if (!lead) {
      return res.status(404).json({ message: 'Lead not found' });
    }

    await warmTenantDEK(lead);

    res.json({
      success: true,
      data: {
        leadId: lead._id,
        buildingType: lead.buildingType,
        source: lead.source,
        status: lead.status,
        estimatorBuildingId: lead.estimatorBuildingId || null,
        marketingConsent: lead.marketingConsent || false,
        createdAt: lead.createdAt,
        updatedAt: lead.updatedAt,
        userInfo: buildPublicUserInfo(lead)
      }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/customer/:leadId/erase?token=<quoteToken>
// Deletes the lead (same logic as the admin eraseLead endpoint) but triggered
// by the customer. Recorded distinctly in AuditLog (actionCategory lead_mgmt).
export async function eraseCustomerLead(req, res, next) {
  try {
    const { leadId } = req.params;

    const lead = await BuildingInfo.findById(leadId);
    if (!lead) {
      return res.status(404).json({ message: 'Lead not found' });
    }

    // Cascading erasure: if this lead came from 3D Estimator, delete the raw building as well
    if (lead.estimatorBuildingId) {
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

    // Same erasure as adminController.eraseLead: a real delete of the lead doc.
    const removed = await BuildingInfo.findByIdAndDelete(leadId);
    // Only decrement when the record is actually removed from the leads collection.
    if (removed && removed.managedByAdmin) await Admin.decrementTotalLeads(removed.managedByAdmin);

    // Distinct audit trail so this is never confused with admin-initiated
    // erasure: actorRole 'customer', action 'lead.erase.customer_initiated'.
    try {
      await AuditLog.create({
        actorId: leadId,
        actorRole: 'customer',
        action: 'lead.erase.customer_initiated',
        actionCategory: 'lead_mgmt',
        targetType: 'building',
        targetId: leadId,
        tenantAdminId: lead.managedByAdmin || null,
        metadata: {
          source: 'customer-rights-token',
          triggeredBy: 'customer'
        },
        ipAddress: validIpOrUndefined(req.ip || (req.headers && req.headers['x-forwarded-for']))
      });
    } catch (auditErr) {
      console.error('Failed to write customer erase audit log:', auditErr.message);
      // Do not fail the erase itself if audit logging fails
    }

    res.json({
      success: true,
      data: { leadId, message: 'Lead erased successfully' }
    });
  } catch (err) {
    next(err);
  }
}

// POST /api/customer/:leadId/correct?token=<quoteToken>
// Allows the customer to correct ONLY their own PII/contact fields. Internal
// fields (status, assignedUsers, managedBy*, owner, notes, ...) are rejected.
export async function correctCustomerLead(req, res, next) {
  try {
    const { leadId } = req.params;
    const body = (req.body && typeof req.body === 'object') ? req.body : {};

    const receivedKeys = Object.keys(body);
    const forbidden = receivedKeys.filter((k) => !ALLOWED_CUSTOMER_FIELDS.includes(k));
    if (forbidden.length > 0) {
      return res.status(400).json({
        message: `Only these fields may be updated: ${ALLOWED_CUSTOMER_FIELDS.join(', ')}. Received disallowed fields: ${forbidden.join(', ')}`
      });
    }

    const lead = await BuildingInfo.findById(leadId);
    if (!lead) {
      return res.status(404).json({ message: 'Lead not found' });
    }

    // Warm the tenant DEK (if resolvable) so the pre-save hook re-encrypts with
    // the same key the data was written under.
    await warmTenantDEK(lead);

    // Apply only the customer-provided fields.
    for (const k of ALLOWED_CUSTOMER_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(body, k)) {
        lead.userInfo[k] = body[k];
      }
    }

    // Re-hydrate the PII fields the customer did NOT touch back to PLAINTEXT so
    // the pre('save') hook encrypts plaintext — never already-encrypted bytes
    // (which would double-encrypt). Getters decrypt with the resolved key.
    if (!Object.prototype.hasOwnProperty.call(body, 'firstName')) lead.userInfo.firstName = lead.getFirstName();
    if (!Object.prototype.hasOwnProperty.call(body, 'lastName')) lead.userInfo.lastName = lead.getLastName();
    if (!Object.prototype.hasOwnProperty.call(body, 'email')) lead.userInfo.email = lead.getEmail();
    if (!Object.prototype.hasOwnProperty.call(body, 'phoneNumber')) lead.userInfo.phoneNumber = lead.getPhone();

    await lead.save();

    res.json({
      success: true,
      data: {
        leadId: lead._id,
        userInfo: buildPublicUserInfo(lead),
        updatedAt: lead.updatedAt
      }
    });
  } catch (err) {
    next(err);
  }
}
