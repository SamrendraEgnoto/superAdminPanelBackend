import mongoose from 'mongoose';

/**
 * Backup Log Model
 * Records every scheduled backup run (success, skipped, or failure) for audit.
 * The encrypted archive lives on disk under <project>/backups/; this collection
 * tracks the outcome, target file, size, and duration of each run.
 */
const BackupLogSchema = new mongoose.Schema({
  // When the run started
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['success', 'failed', 'skipped'],
    required: true
  },
  fileName: {
    type: String,
    default: null
  },
  fileSize: {
    type: Number,
    default: 0
  },
  error: {
    type: String,
    default: null
  },
  durationMs: {
    type: Number,
    default: 0
  }
});

BackupLogSchema.index({ timestamp: -1 });

export default mongoose.model('BackupLog', BackupLogSchema);