/**
 * Encrypted Scheduled Backup Job
 * Performs mongodump, encrypts the backup, tracks runs in backup_runs collection.
 * Key distinction: backup encryption key is separate from field-level encryption keys.
 * Retention policy configurable per environment.
 */

require('dotenv').config();
const { execSync } = require('child_process');
const { writeFileSync, readFileSync, unlinkSync, mkdirSync } = require('fs');
const { randomBytes, createHmac } = require('crypto');
const mongoose = require('mongoose');
const BackupRun = mongoose.model('BackupRun', new mongoose.Schema({
  startTime: { type: Date, default: Date.now },
  endTime: { type: Date },
  status: { type: String, enum: ['success', 'failure'], default: 'failure' },
  encrypted: { type: Boolean, default: false },
  storageLocation: { type: String },
  sizeBytes: { type: Number },
  keyId: { type: String }, // Distinct backup key reference
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
}, { timestamps: true }));

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/super_admin_panel';
const BACKUP_DIR = process.env.BACKUP_DIR || './backups';
const BACKUP_RETENTION_DAYS = parseInt(process.env.BACKUP_RETENTION_DAYS) || 30;
const BACKUP_ENCRYPTION_KEY = process.env.BACKUP_ENCRYPTION_KEY; // Distinct from field-level keys

if (!BACKUP_ENCRYPTION_KEY) {
  console.error('❌ BACKUP_ENCRYPTION_KEY environment variable not set');
  process.exit(1);
}

mkdirSync(BACKUP_DIR, { recursive: true });

(async () => {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('🔐 Connected to MongoDB');

    const run = await BackupRun.create({
      status: 'running',
      encrypted: false,
      storageLocation: '',
      sizeBytes: 0,
      keyId: randomBytes(16).toString('hex'),
      adminId: null
    });

    const startTime = new Date();
    console.log(`📦 Backup run #${run._id} started at ${startTime}`);

    // 1. Run mongodump
    const dumpPath = `${BACKUP_DIR}/backup_${run._id}.json`;
    try {
      execSync(
        `mongodump --uri="${MONGODB_URI}" --out="${dumpPath}" --archive=true`,
        { stdio: 'pipe' }
      );
      console.log('📦 mongodump completed');
    } catch (err) {
      console.error('❌ mongodump failed:', err.message);
      await BackupRun.updateOne({ _id: run._id }, {
        status: 'failure',
        endTime: new Date()
      });
      await mongoose.disconnect();
      process.exit(1);
    }

    // 2. Encrypt the backup file
    const encryptedPath = `${BACKUP_DIR}/backup_${run._id}.enc`;
    try {
      const input = readFileSync(dumpPath);
      const iv = randomBytes(16);
      const hmac = createHmac('sha256', BACKUP_ENCRYPTION_KEY).update(input).digest('base64');
      const cipher = createCipheriv('aes-256-gcm', BACKUP_ENCRYPTION_KEY, iv);
      const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
      const authTag = cipher.getAuthTag();
      
      // Write: iv (16 bytes) + authTag (16 bytes) + encrypted data
      const encryptedBuffer = Buffer.concat([iv, authTag, encrypted]);
      writeFileSync(encryptedPath, encryptedBuffer);
      
      unlinkSync(dumpPath); // Remove unencrypted dump
      console.log('🔒 Backup encrypted');
    } catch (err) {
      console.error('❌ Backup encryption failed:', err.message);
      await BackupRun.updateOne({ _id: run._id }, {
        status: 'failure',
        endTime: new Date()
      });
      await mongoose.disconnect();
      process.exit(1);
    }

    // 3. Update run record
    const endTime = new Date();
    const sizeBytes = readFileSync(encryptedPath).length;
    
    await BackupRun.updateOne({ _id: run._id }, {
      status: 'success',
      encrypted: true,
      storageLocation: encryptedPath,
      sizeBytes,
      endTime
    });

    console.log(`✅ Backup run #${run._id} completed`);
    console.log(`   - Encrypted: true`);
    console.log(`   - Storage: ${encryptedPath}`);
    console.log(`   - Size: ${sizeBytes} bytes (${(sizeBytes / 1024 / 1024).toFixed(2)} MB)`);
    console.log(`   - Key ID: ${run.keyId}`);

    // 4. Retention cleanup
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - BACKUP_RETENTION_DAYS);
    
    // Find and remove old backup files
    const oldBackups = await BackupRun.find({ endTime: { $lt: cutoffDate }, status: 'success' });
    for (const oldRun of oldBackups) {
      const oldPath = oldRun.storageLocation;
      if (oldPath && require('fs').existsSync(oldPath)) {
        unlinkSync(oldPath);
        console.log(`🗑️ Removed old backup: ${oldPath}`);
      }
      await BackupRun.deleteOne({ _id: oldRun._id });
    }
    console.log(`🧹 Cleaned up ${oldBackups.length} old backup(s) (retention: ${BACKUP_RETENTION_DAYS} days)`);

    await mongoose.disconnect();
    console.log('🎉 Backup job completed successfully');
  } catch (error) {
    console.error('❌ Backup job failed:', error.message);
    process.exit(1);
  }
})();
