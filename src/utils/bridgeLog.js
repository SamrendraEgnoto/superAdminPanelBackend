/**
 * Bridge Call Logger
 * Logs every Super Admin Panel ↔ Estimator_Node bridge call
 * for audit and monitoring purposes (Section 10).
 *
 * Each call is written to the persisted `BridgeLog` collection (queryable) in
 * addition to the console so bridge activity is traceable. Persistence is
 * fire-and-forget — a DB failure never breaks the caller.
 */
import BridgeLog from '../models/BridgeLog.js';

const sanitizePayload = (value) => {
  try {
    return JSON.stringify(value ?? {});
  } catch {
    return String(value ?? '');
  }
};

// Write a log entry to the BridgeLog collection (non-blocking).
const persist = (entry) => {
  BridgeLog.create({
    actorType: entry.actorType || 'system',
    adminId: entry.adminId || null,
    estimatorBuildingId: entry.estimatorBuildingId || entry.leadId || null,
    event: entry.event,
    direction: entry.direction,
    endpoint: entry.endpoint,
    status: entry.status,
    error: entry.error || null,
    raw: sanitizePayload(entry),
    timestamp: new Date(entry.timestamp),
  }).catch((err) => {
    console.error('[Bridge Log] Failed to persist bridge log:', err.message);
  });
  return entry;
};

const bridgeLog = {
  // Log format: [timestamp] [direction] [status] [endpoint] [details]
  direction: 'unknown',

  /**
   * Log an outbound call from Super Admin Panel to Estimator_Node
   */
  logOutboundCall(endpoint, status, error = null, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      direction: 'sa-to-en',
      endpoint,
      status, // 'success' or 'failure'
      error: error ? error.message : null,
      event: details.event || `bridge_outbound_${status}`,
      ...details
    };
    console.log(`[Bridge Log] OUT: ${JSON.stringify(entry)}`);
    return persist(entry);
  },

  /**
   * Log an inbound call to Super Admin Panel from Estimator_Node
   */
  logInboundCall(endpoint, status, error = null, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      direction: 'en-to-sa',
      endpoint,
      status, // 'success' or 'failure'
      error: error ? error.message : null,
      event: details.event || `bridge_inbound_${status}`,
      ...details
    };
    console.log(`[Bridge Log] IN: ${JSON.stringify(entry)}`);
    return persist(entry);
  }
};

export default bridgeLog;
