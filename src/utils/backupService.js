import nodeCron from 'node-cron';
import { exec as execCallback } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import BuildingInfo from '../models/BuildingInfo.js';
import Admin from '../models/Admin.js';
import Settings from '../models/Settings.js';
import BackupLog from '../models/BackupLog.js';

const exec = promisify(execCallback);

const DAY_MS = 24 * 60 * 60 * 1000;
// Global default retention window when an Admin has no retentionDays set.
const GLOBAL_RETENTION_DAYS = 90;

/**
 * Backup Service
 * Handles automated database backups and retention.
 * Backups are encrypted using OpenSSL AES-256-CBC with a key derived from ENCRYPTION_MASTER_KEY.
 *
 * Schedule (server local time):
 *  - 02:00  purge BuildingInfo records past each Admin's retention window
 *  - 03:00  encrypted mongodump backup (every run is logged to BackupLog)
 */
class BackupService {
  constructor() {
    this.backupDir = path.join(process.cwd(), 'backups');
    this.backupInProgress = false;
    this.init();
  }

  init() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }

    // Purge BuildingInfo records past each Admin's retention window (daily at 2am)
    this.job = nodeCron.schedule('0 2 * * *', () => this.purgeOldBuildingInfo());

    // Encrypted database backup (daily at 3am). Every run — success, skipped,
    // or failure — is persisted to the BackupLog collection for audit.
    this.backupJob = nodeCron.schedule('0 3 * * *', () => this.runScheduledBackup());

    console.log('Backup Service Initialized');
  }

  /**
   * Resolve the mongodump executable (PATH first, then common install paths).
   * @returns {Promise<string|null>} command to invoke, or null if unavailable
   */
  async resolveMongodump() {
    try {
      await exec('mongodump --version', { timeout: 10000 });
      return 'mongodump';
    } catch (err) {
      // fall through to known install paths
    }

    const commonPaths = [
      '/opt/homebrew/bin/mongodump',
      '/usr/local/bin/mongodump',
      '/usr/bin/mongodump',
      'C:\\Program Files\\MongoDB\\Tools\\100\\bin\\mongodump.exe',
      'C:\\Program Files\\MongoDB\\Database Tools\\bin\\mongodump.exe'
    ];
    return commonPaths.find(p => fs.existsSync(p)) || null;
  }

  /**
   * Run the backup process.
   * - mongodump -> single gzipped archive file (--archive)
   * - encrypt the archive with OpenSSL AES-256-CBC -> .gz.enc
   * - remove the raw archive, then apply retention cleanup
   *
   * Returns a result object on success/skip and throws on failure so the
   * caller (runScheduledBackup) can record the outcome in BackupLog.
   * @returns {Promise<{status:string, fileName?:string, filePath?:string, fileSize?:number, reason?:string}>}
   */
  async runBackup() {
    if (this.backupInProgress) {
      console.log('Backup already in progress; skipping this run');
      return { status: 'skipped', reason: 'Backup already in progress' };
    }

    this.backupInProgress = true;
    try {
      return await this._runBackupInternal();
    } finally {
      this.backupInProgress = false;
    }
  }

  async _runBackupInternal() {
    const settings = await Settings.findOne({ userId: null });
    const retentionDays = settings?.system?.retentionPeriod || 90;

    if (settings && !settings.system.autoBackup) {
      console.log('Skipping automatic backup (disabled in settings)');
      return { status: 'skipped', reason: 'Automatic backup disabled in settings' };
    }

    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      throw new Error('MONGO_URI not found, cannot perform backup');
    }

    const mongodumpCmd = await this.resolveMongodump();
    if (!mongodumpCmd) {
      throw new Error('mongodump is not installed or not in the system PATH');
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archivePath = path.join(this.backupDir, `backup-${timestamp}.gz`);
    const encryptedBackupPath = `${archivePath}.enc`;
    const opensslPassword = process.env.ENCRYPTION_MASTER_KEY || 'backup-key-change-me';
    const dbFlag = process.env.BACKUP_DATABASE ? ` --db="${process.env.BACKUP_DATABASE}"` : '';

    console.log(`Starting backup -> ${archivePath}...`);

    // 1) mongodump -> single gzipped archive file
    await exec(`"${mongodumpCmd}" --uri="${mongoUri}"${dbFlag} --archive="${archivePath}" --gzip`);
    if (!fs.existsSync(archivePath)) {
      throw new Error('mongodump exited cleanly but produced no archive file');
    }
    console.log(`Raw backup completed: ${archivePath}`);

    // 2) Encrypt the archive using OpenSSL AES-256-CBC
    await exec(`openssl enc -aes-256-cbc -salt -pass pass:${opensslPassword} -in "${archivePath}" -out "${encryptedBackupPath}"`);

    // 3) Remove the unencrypted archive + apply retention cleanup
    fs.rmSync(archivePath, { force: true });
    this.cleanupOldBackups(retentionDays);

    const stats = fs.statSync(encryptedBackupPath);
    console.log(`Backup encrypted: ${encryptedBackupPath}`);

    return {
      status: 'success',
      fileName: path.basename(encryptedBackupPath),
      filePath: encryptedBackupPath,
      fileSize: stats.size
    };
  }

  /**
   * Scheduled entry point (cron). Runs the backup and records the outcome in
   * BackupLog so every run is auditable — success, skipped, or failure.
   * @returns {Promise<object>} runBackup result (never throws)
   */
  async runScheduledBackup() {
    const startedAt = Date.now();
    try {
      const result = await this.runBackup();
      await BackupLog.create({
        status: result.status,
        fileName: result.fileName || null,
        fileSize: result.fileSize || 0,
        error: result.status === 'skipped' ? (result.reason || 'skipped') : null,
        durationMs: Date.now() - startedAt
      });
      console.log(`Backup run logged [${result.status}] in ${Date.now() - startedAt}ms`);
      return result;
    } catch (error) {
      console.error('Scheduled backup failed:', error.message);
      await BackupLog.create({
        status: 'failed',
        error: error.message,
        durationMs: Date.now() - startedAt
      });
      return { status: 'failed', error: error.message };
    }
  }

  /**
   * Remove backups older than the retention period
   * @param {number} days
   */
  cleanupOldBackups(days) {
    const retentionMs = days * 24 * 60 * 60 * 1000;
    const now = Date.now();

    fs.readdir(this.backupDir, (err, files) => {
      if (err) {
        console.error('Error reading backup directory:', err);
        return;
      }

      files.forEach(file => {
        const filePath = path.join(this.backupDir, file);
        fs.stat(filePath, (err, stats) => {
          if (err) return;

          // Apply retention to both .gz and .gz.enc files
          if (now - stats.mtimeMs > retentionMs) {
            console.log(`Deleting old backup: ${file}`);
            fs.rmSync(filePath, { recursive: true, force: true });
          }
        });
      });
    });
  }

  /**
   * Purge BuildingInfo records past each Admin's retention window.
   *
   * Every lead is cut off by the window of the Admin that owns it
   * (lead.managedByAdmin -> Admin.retentionDays). Admins with no retentionDays
   * set fall back to the global default (90 days). Leads not owned by any
   * existing Admin (orphaned / deleted tenant) also fall back to the global
   * default, so nothing is kept forever because its tenant disappeared.
   */
  async purgeOldBuildingInfo() {
    const now = Date.now();

    try {
      // Get all Admins with their retentionDays
      const admins = await Admin.find({}, 'retentionDays _id').lean();
      const knownAdminIds = [];

      for (const admin of admins) {
        knownAdminIds.push(admin._id);

        // Tenant-specific window: this Admin's retentionDays, or the global default.
        const retentionDays = admin.retentionDays || GLOBAL_RETENTION_DAYS;
        const cutoff = new Date(now - retentionDays * DAY_MS);

        // Purge BuildingInfo records managed by this Admin older than retention
        const result = await BuildingInfo.deleteMany({
          managedByAdmin: admin._id,
          createdAt: { $lt: cutoff }
        });

        // Hard purged records leave the leads collection -> keep the counter in sync.
        if (result.deletedCount > 0) await Admin.decrementTotalLeads(admin._id, result.deletedCount);

        console.log(`Purged ${result.deletedCount} BuildingInfo records for Admin ${admin._id} (retention: ${retentionDays} days)`);
      }

      // Orphaned leads (no owner / owner no longer exists) use the global default.
      const orphanCutoff = new Date(now - GLOBAL_RETENTION_DAYS * DAY_MS);
      const orphanResult = await BuildingInfo.deleteMany({
        createdAt: { $lt: orphanCutoff },
        $or: [
          { managedByAdmin: null },
          { managedByAdmin: { $nin: knownAdminIds } }
        ]
      });
      if (orphanResult.deletedCount > 0) {
        console.log(`Purged ${orphanResult.deletedCount} orphaned BuildingInfo records (global retention: ${GLOBAL_RETENTION_DAYS} days)`);
      }
    } catch (error) {
      console.error('Error purging old BuildingInfo records:', error);
    }
  }

  /**
   * Update the backup cron schedule based on settings.
   * @param {string} frequency - 'daily', 'weekly', 'monthly'
   */
  updateSchedule(frequency) {
    let cronExpression = '0 3 * * *'; // Default daily at 3am

    if (frequency === 'weekly') {
      cronExpression = '0 3 * * 0'; // Sunday at 3am
    } else if (frequency === 'monthly') {
      cronExpression = '0 3 1 * *'; // 1st of every month at 3am
    }

    if (this.backupJob) {
      this.backupJob.stop();
    }

    this.backupJob = nodeCron.schedule(cronExpression, () => this.runScheduledBackup());
    console.log(`Backup schedule updated to: ${frequency} (${cronExpression})`);
  }
}

export default new BackupService();