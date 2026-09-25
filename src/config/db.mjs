import mongoose from 'mongoose';
import dns from 'dns';

// Fix for Windows/local DNS that fails SRV/TXT lookups for mongodb+srv://
// Node defaults to 127.0.0.1 which ECONNREFUSED SRV; force public resolvers.
try {
  if (dns.getServers().length === 1 && dns.getServers()[0] === '127.0.0.1') {
    dns.setServers(['8.8.8.8', '1.1.1.1']);
    console.log('[db] DNS servers overridden to', dns.getServers());
  }
} catch { }

const primaryUri = process.env.MONGO_URI;
const secondaryUri = process.env.SECONDARY_MONGO_URI || '';

async function connectDB() {
  if (!primaryUri) {
    console.error('MONGO_URI not set in environment variables');
    process.exit(1);
  }
  try {
    await mongoose.connect(primaryUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected (primary):', mongoose.connection.name);
  } catch (err) {
    console.error('MongoDB primary connection failed:', err);
    process.exit(1);
  }

  // Ensure collections and indexes on the active unified database (Estimator_Manager)
  const activeDbName = mongoose.connection.name || 'Estimator_Manager';
  const primaryDb = mongoose.connection.useDb(activeDbName);

  // Use catch to handle if collections already exist
  try { primaryDb.createCollection('super_admins'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.super_admins.createIndex({ email: 1 }, { unique: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.super_admins.createIndex({ createdById: 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('admins'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.admins.createIndex({ emailHash: 1 }, { unique: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.admins.createIndex({ subdomain: 1 }, { unique: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.admins.createIndex({ customDomain: 1 }, { unique: true, sparse: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.admins.createIndex({ createdById: 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('users'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.users.createIndex({ adminId: 1, emailHash: 1 }, { unique: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.users.createIndex({ adminId: 1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.users.createIndex({ parentUserId: 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('leads'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.leads.createIndex({ managedByAdminId: 1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.leads.createIndex({ managedBySuperAdminId: 1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.leads.createIndex({ estimatorBuildingId: 1 }, { unique: true, sparse: true }); } catch (e) { /* index may already exist */ }
  try { primaryDb.leads.createIndex({ managedByAdminId: 1, status: 1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.leads.createIndex({ 'assignedUsers.userId': 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('settings'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.settings.createIndex({ adminId: 1 }, { unique: true, sparse: true }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('otps'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.otps.createIndex({ createdAt: 1 }, { expireAfterSeconds: 600 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.otps.createIndex({ email: 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('audit_logs'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.audit_logs.createIndex({ tenantAdminId: 1, timestamp: -1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.audit_logs.createIndex({ actorId: 1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.audit_logs.createIndex({ actionCategory: 1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('backup_runs'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.backup_runs.createIndex({ startedAt: -1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('backup_logs'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.backup_logs.createIndex({ timestamp: -1 }); } catch (e) { /* index may already exist */ }

  try { primaryDb.createCollection('bridge_logs'); } catch (e) { /* collection may already exist */ }
  try { primaryDb.bridge_logs.createIndex({ adminId: 1, timestamp: -1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.bridge_logs.createIndex({ event: 1, timestamp: -1 }); } catch (e) { /* index may already exist */ }
  try { primaryDb.bridge_logs.createIndex({ status: 1 }); } catch (e) { /* index may already exist */ }

  console.log('Primary database collections ensured');

  // Optional secondary database (estimator_platform) - graceful handling
  if (secondaryUri && secondaryUri.trim()) {
    try {
      const secondaryConn = mongoose.createConnection(secondaryUri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });

      await new Promise((resolve, reject) => {
        secondaryConn.once('open', resolve);
        secondaryConn.on('error', reject);
      });

      console.log('MongoDB connected (secondary):', secondaryConn.name);
      global.secondaryDb = secondaryConn;

      const secondaryDb = secondaryConn.useDb('estimator_platform');
      if (secondaryDb) {
        try { secondaryDb.createCollection('tenants'); } catch (e) { }
        try { secondaryDb.tenants.createIndex({ tenantId: 1 }, { unique: true }); } catch (e) { }
        try { secondaryDb.tenants.createIndex({ subdomain: 1 }, { unique: true }); } catch (e) { }
        try { secondaryDb.tenants.createIndex({ customDomain: 1 }, { unique: true, sparse: true }); } catch (e) { }

        try { secondaryDb.createCollection('buildings'); } catch (e) { }
        try { secondaryDb.buildings.createIndex({ tenantId: 1 }); } catch (e) { }
        try { secondaryDb.buildings.createIndex({ leadId: 1 }); } catch (e) { }
        try { secondaryDb.buildings.createIndex({ tenantId: 1, buildingType: 1 }); } catch (e) { }

        try { secondaryDb.createCollection('building_options'); } catch (e) { }
        try { secondaryDb.building_options.createIndex({ tenantId: 1 }, { unique: true }); } catch (e) { }

        try { secondaryDb.createCollection('building_type_images'); } catch (e) { }
        try { secondaryDb.building_type_images.createIndex({ tenantId: 1, buildingType: 1 }, { unique: true }); } catch (e) { }

        try { secondaryDb.createCollection('states'); } catch (e) { }
        try { secondaryDb.states.createIndex({ state: 1 }, { unique: true }); } catch (e) { }
      }

      console.log('Secondary database collections ensured');
    } catch (err) {
      console.error('MongoDB secondary connection error:', err.message);
      // Continue without secondary - primary is critical
    }
  }
}

export default connectDB;
