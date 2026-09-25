import mongoose from 'mongoose';

// Persisted log of each Super Admin Panel ↔ Estimator_Node bridge call so bridge
// activity is queryable (not just console-visible via utils/bridgeLog.js).
const BridgeLogSchema = new mongoose.Schema({
  actorType: { type: String, default: 'system' },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  estimatorBuildingId: { type: String, default: null },
  event: { type: String, required: true },
  direction: { type: String, enum: ['sa-to-en', 'en-to-sa', 'unknown'], default: 'unknown' },
  endpoint: { type: String },
  status: { type: String, enum: ['success', 'failure', 'pending', 'idempotent', 'unknown'], default: 'unknown' },
  error: { type: String },
  raw: { type: String }, // payload summary (JSON snapshot) for tracing
  timestamp: { type: Date, default: Date.now },
});

BridgeLogSchema.index({ adminId: 1, timestamp: -1 });
BridgeLogSchema.index({ event: 1, timestamp: -1 });
BridgeLogSchema.index({ status: 1 });

export default mongoose.model('BridgeLog', BridgeLogSchema);
