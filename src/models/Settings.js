import mongoose from 'mongoose';

/**
 * Settings Model
 * Stores system-wide and user-specific configurations for:
 * - Notifications
 * - Appearance
 * - System (Backups)
 * - Integration (SMTP)
 */
const SettingsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Can be Admin or SuperAdmin or User
    default: null // null indicates global/system settings
  },
  notifications: {
    emailNotifications: { type: Boolean, default: true },
    pushNotifications: { type: Boolean, default: false },
    weeklyReports: { type: Boolean, default: true },
    newLeadAlerts: { type: Boolean, default: true },
  },
  appearance: {
    theme: { type: String, default: 'dark' },
    compactMode: { type: Boolean, default: false },
    sidebarCollapsed: { type: Boolean, default: false },
  },
  system: {
    autoBackup: { type: Boolean, default: true },
    backupFrequency: { type: String, enum: ['daily', 'weekly', 'monthly'], default: 'daily' },
    retentionPeriod: { type: Number, default: 90 }, // in days
  },
  integration: {
    emailProvider: { type: String, default: 'smtp' },
    smtpHost: { type: String, default: '' },
    smtpPort: { type: String, default: '587' },
    smtpUser: { type: String, default: '' },
    smtpPassword: { type: String, default: '' },
    fromAddress: { type: String, default: 'no-reply@egnoto.com' },
    isVerified: { type: Boolean, default: false },
  },
  updatedAt: { type: Date, default: Date.now }
});

// Update the updatedAt field on save
SettingsSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.model('Settings', SettingsSchema);
