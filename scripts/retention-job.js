/**
 * Data Retention Scheduled Job
 * Purges leads past each Admin's retention window.
 * Read per-Admin retentionDays, not one global constant.
 */

require('dotenv').config();
const mongoose = require('mongoose');
const BuildingInfo = mongoose.model('BuildingInfo', require('./src/models/BuildingInfo.js').default);
const Admin = mongoose.model('Admin', require('./src/models/Admin.js').default);

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/super_admin_panel';

(async () => {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // 1. Fetch all Admins with their retentionDays
    const admins = await Admin.find({}, 'retentionDays _id').lean();
    console.log(`📋 Found ${admins.length} Admins to process`);

    let totalPurged = 0;

    for (const admin of admins) {
      const retentionDays = admin.retentionDays || 365; // default to 365
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      // 2. Purge leads past the retention window for this Admin
      const result = await BuildingInfo.deleteMany({
        managedByAdmin: admin._id,
        createdAt: { $lt: cutoffDate }
      });

      const purgedCount = result.deletedCount;
      totalPurged += purgedCount;

      if (purgedCount > 0) {
        console.log(`🗑️ Admin ${admin._id} (retention: ${retentionDays} days): purged ${purgedCount} leads`);
      }
    }

    console.log(`🧹 Total leads purged across all tenants: ${totalPurged}`);
    await mongoose.disconnect();
    console.log('✅ Data retention job completed');
  } catch (error) {
    console.error('❌ Data retention job failed:', error.message);
    process.exit(1);
  }
})();
