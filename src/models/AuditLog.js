import mongoose from 'mongoose';

const AuditLogSchema = new mongoose.Schema({
  actorId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'actorRole',
    required: true
  },
  actorRole: {
    type: String,
    enum: ['superadmin', 'admin', 'user', 'customer', 'system', 'delegated', 'root'],
    required: true
  },
  // Free-text action (e.g. 'user.create', 'lead.assign', 'domain.verify').
  // Intentionally NOT an enum — call sites may introduce new actions without
  // a model migration. Filtering/aggregation is done via actionCategory.
  action: {
    type: String,
    required: true
  },
  actionCategory: {
    type: String,
    enum: ['auth', 'user_mgmt', 'admin_mgmt', 'lead_mgmt', 'domain', 'settings', 'recovery', 'internal_api', 'other'],
    default: 'other'
  },
  targetType: {
    type: String,
    enum: [
      'superadmin',
      'admin',
      'user',
      'building',   // BuildingInfo/lead
      'setting',
      'kms_config',
      'bridge_call'
    ]
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'targetType'
  },
  tenantAdminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  ipAddress: {
    type: String,
    // IPv4 or IPv6 format
    match: [/^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|::1|[0-9a-f:]+$/i, 'Please provide a valid IP address']
  }
});

// Indexes for common query patterns
// No TTL — this collection must persist indefinitely for compliance
AuditLogSchema.index({ actorId: 1, actorRole: 1, timestamp: -1 });
AuditLogSchema.index({ action: 1, timestamp: -1 });
AuditLogSchema.index({ targetType: 1, targetId: 1, timestamp: -1 });
AuditLogSchema.index({ tenantAdminId: 1, timestamp: -1 });

export default mongoose.model('AuditLog', AuditLogSchema);