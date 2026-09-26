import mongoose from 'mongoose';
import { encryptField, decryptField, hashEmail } from '../utils/encryption.js';
import { getTenantDEK, ensureTenantDEK, getAllCachedDEKs } from '../services/tenantCrypto.js';

// Helper: get admin or super admin ID string for encryption key derivation
const getAdminIdString = (doc) => {
  try {
    if (!doc) return '';
    const raw = doc.managedByAdmin || doc.managedBySuperAdmin;
    if (!raw) return '';
    if (typeof raw === 'object' && raw !== null) {
      return (raw._id ? raw._id.toString() : raw.toString());
    }
    return raw.toString();
  } catch {
    return '';
  }
};

// ================= SCHEMA DEFINITION =================
const BuildingInfoSchema = new mongoose.Schema({
  buildingType: { type: String },
  userInfo: {
    email: { type: mongoose.Schema.Types.Mixed },
    phoneNumber: { type: mongoose.Schema.Types.Mixed },
    phone: { type: mongoose.Schema.Types.Mixed },
    firstName: { type: mongoose.Schema.Types.Mixed },
    lastName: { type: mongoose.Schema.Types.Mixed },
    emailHash: { type: String, index: true },
    firstNameHash: { type: String, index: true },
    lastNameHash: { type: String, index: true },
    address: { type: mongoose.Schema.Types.Mixed },
    city: { type: mongoose.Schema.Types.Mixed },
    state: { type: mongoose.Schema.Types.Mixed },
    zip: { type: mongoose.Schema.Types.Mixed }
  },
  source: { type: String },
  managedByAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  managedBySuperAdmin: { type: mongoose.Schema.Types.ObjectId, ref: 'SuperAdmin' },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  estimatorBuildingId: { type: String },
  status: { type: String, default: 'new' },
  marketingConsent: { type: Boolean, default: false },
  // GDPR/CCPA/DPDP consent recorded when the 3D Estimator captures it from the end-user
  consentGiven: { type: Boolean },
  consentTimestamp: { type: Date },
  consentTextVersion: { type: String },
  permissionLevel: { type: String, default: 'read' },
  assignedUsers: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    permissions: [{ type: String }]
  }],
  notes: { type: String },
  estimatorData: { type: mongoose.Schema.Types.Mixed },
  attributes: { type: mongoose.Schema.Types.Mixed, default: {} },
  activities: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String },
    details: { type: String },
    timestamp: { type: Date, default: Date.now }
  }],

  // ===== Lead Sharing (Delegated SA → Data-Viewer Admin) =====
  sharedWith: [{
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    sharedAt: { type: Date, default: Date.now },
    sharedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'SuperAdmin', required: true },
    note: { type: String, default: '' }
  }],

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { strict: false });

const resolveFieldDecrypted = (val, adminId) => {
  if (!val) return '';
  // If already clean plaintext (e.g. readable name or email with @)
  if (typeof val === 'string' && val.includes('@')) return val;

  const dek = adminId ? getTenantDEK(adminId) : null;
  if (dek) {
    const decrypted = decryptField(val, dek);
    if (decrypted) return decrypted;
  }

  // Try all cached DEKs if specific tenant key didn't match (for cross-tenant/DSA leads)
  const cachedDeks = getAllCachedDEKs();
  for (const cDek of cachedDeks) {
    const decrypted = decryptField(val, cDek);
    if (decrypted) return decrypted;
  }

  const legacy = decryptField(val);
  if (legacy) return legacy;

  if (typeof val === 'string' && val.length > 0 && !val.startsWith('gcm:') && !val.startsWith('{') && !/^[A-Za-z0-9+/=]{40,}$/.test(val)) {
    return val;
  }
  return '';
};

const decryptAssignedUsersList = (assignedUsers, fallbackAdminId) => {
  if (!Array.isArray(assignedUsers)) return assignedUsers;
  return assignedUsers.map((item) => {
    if (!item) return item;
    const rawUser = item.user;
    if (rawUser && typeof rawUser === 'object') {
      const u = typeof rawUser.toObject === 'function' ? rawUser.toObject() : { ...rawUser };
      const uAdminId = (u.adminId || u.createdBy || fallbackAdminId || '').toString();

      const fName = resolveFieldDecrypted(u.firstName, uAdminId) || u.firstName || '';
      const lName = resolveFieldDecrypted(u.lastName, uAdminId) || u.lastName || '';
      const email = resolveFieldDecrypted(u.email, uAdminId) || u.email || '';
      const phone = resolveFieldDecrypted(u.phone || u.phoneNumber, uAdminId) || u.phone || u.phoneNumber || '';

      return {
        ...item,
        user: {
          ...u,
          firstName: fName,
          lastName: lName,
          email,
          phone,
          phoneNumber: phone
        }
      };
    }
    return item;
  });
};

// Helper instance method to get decrypted firstName
BuildingInfoSchema.methods.getFirstName = function () {
  if (this.userInfo && this.userInfo.firstName) {
    const adminId = getAdminIdString(this);
    return resolveFieldDecrypted(this.userInfo.firstName, adminId);
  }
  return '';
};

// Helper instance method to get decrypted lastName
BuildingInfoSchema.methods.getLastName = function () {
  if (this.userInfo && this.userInfo.lastName) {
    const adminId = getAdminIdString(this);
    return resolveFieldDecrypted(this.userInfo.lastName, adminId);
  }
  return '';
};

// Helper instance method to get decrypted email
BuildingInfoSchema.methods.getEmail = function () {
  if (this.userInfo && this.userInfo.email) {
    const adminId = getAdminIdString(this);
    return resolveFieldDecrypted(this.userInfo.email, adminId);
  }
  return '';
};

// Helper instance method to get decrypted phone
BuildingInfoSchema.methods.getPhone = function () {
  if (this.userInfo) {
    const raw = this.userInfo.phoneNumber || this.userInfo.phone;
    const adminId = getAdminIdString(this);
    return resolveFieldDecrypted(raw, adminId);
  }
  return '';
};

// Override toJSON to return decrypted data for API responses
BuildingInfoSchema.methods.toJSON = function () {
  const obj = this.toObject({ transform: false });
  const email = this.getEmail();
  const phone = this.getPhone();
  const firstName = this.getFirstName();
  const lastName = this.getLastName();

  obj.email = email;
  obj.phone = phone;
  obj.phoneNumber = phone;
  obj.firstName = firstName;
  obj.lastName = lastName;

  if (obj.userInfo) {
    obj.userInfo.email = email;
    obj.userInfo.phoneNumber = phone;
    obj.userInfo.phone = phone;
    obj.userInfo.firstName = firstName;
    obj.userInfo.lastName = lastName;
    delete obj.userInfo.emailHash;
  }

  obj.assignedUsers = decryptAssignedUsersList(obj.assignedUsers, getAdminIdString(this));

  return obj;
};

BuildingInfoSchema.set('toObject', {
  transform: function (doc, ret) {
    const email = doc.getEmail ? doc.getEmail() : ret.email;
    const phone = doc.getPhone ? doc.getPhone() : (ret.phone || ret.phoneNumber);
    const firstName = doc.getFirstName ? doc.getFirstName() : ret.firstName;
    const lastName = doc.getLastName ? doc.getLastName() : ret.lastName;

    ret.email = email;
    ret.phone = phone;
    ret.phoneNumber = phone;
    ret.firstName = firstName;
    ret.lastName = lastName;

    if (ret.userInfo) {
      ret.userInfo.email = email;
      ret.userInfo.phoneNumber = phone;
      ret.userInfo.phone = phone;
      ret.userInfo.firstName = firstName;
      ret.userInfo.lastName = lastName;
      delete ret.userInfo.emailHash;
    }

    ret.assignedUsers = decryptAssignedUsersList(ret.assignedUsers, getAdminIdString(doc));

    return ret;
  }
});

// ================= ENCRYPTION HOOK: encrypt PII before saving, hash email/name for lookup =================
BuildingInfoSchema.pre('save', async function (next) {
  try {
    const adminIdString = getAdminIdString(this);

    // Normalize phone and phoneNumber on userInfo
    if (this.userInfo) {
      if (!this.userInfo.phoneNumber && this.userInfo.phone) {
        this.userInfo.phoneNumber = this.userInfo.phone;
      } else if (this.userInfo.phoneNumber && !this.userInfo.phone) {
        this.userInfo.phone = this.userInfo.phoneNumber;
      }
    }

    // Resolve the tenant DEK first (unwraps via passkey session or recovers via Vault/KMS)
    const dek = adminIdString ? await ensureTenantDEK(adminIdString) : null;

    // Capture PLAINTEXT before encryption so hashes index the searchable value
    const plain = this.userInfo
      ? {
          email: this.userInfo.email,
          phoneNumber: this.userInfo.phoneNumber,
          firstName: this.userInfo.firstName,
          lastName: this.userInfo.lastName
        }
      : {};

    const infoModified = this.isNew
      || this.isModified('userInfo')
      || this.isModified('userInfo.email')
      || this.isModified('userInfo.phoneNumber')
      || this.isModified('userInfo.phone')
      || this.isModified('userInfo.firstName')
      || this.isModified('userInfo.lastName');

    if (infoModified && this.userInfo) {
      // Guard against double encrypting already-encrypted strings or objects
      const shouldEncrypt = (val) => {
        if (!val || typeof val !== 'string' || val.length === 0) return false;
        if (val.startsWith('gcm:') || val.startsWith('{')) return false;
        if (val.length >= 44 && /^[A-Za-z0-9+/=]+$/.test(val) && !val.includes(' ') && !val.includes('@')) {
          return false;
        }
        return true;
      };

      if (shouldEncrypt(plain.email)) {
        const encrypted = encryptField(plain.email, dek);
        if (encrypted) this.userInfo.email = encrypted;
      }

      if (shouldEncrypt(plain.phoneNumber)) {
        const encryptedPhone = encryptField(plain.phoneNumber, dek);
        if (encryptedPhone) {
          this.userInfo.phoneNumber = encryptedPhone;
          this.userInfo.phone = encryptedPhone;
        }
      }

      if (shouldEncrypt(plain.firstName)) {
        const encryptedFirstName = encryptField(plain.firstName, dek);
        if (encryptedFirstName) this.userInfo.firstName = encryptedFirstName;
      }

      if (shouldEncrypt(plain.lastName)) {
        const encryptedLastName = encryptField(plain.lastName, dek);
        if (encryptedLastName) this.userInfo.lastName = encryptedLastName;
      }

      this.markModified('userInfo');
    }

    // Add hashed email/name lookup fields (stored in plaintext for searching)
    if (plain.email && plain.email.includes('@')) {
      this.userInfo.emailHash = hashEmail(plain.email);
    }
    if (plain.firstName && plain.firstName.length < 60) {
      this.userInfo.firstNameHash = hashEmail(plain.firstName);
    }
    if (plain.lastName && plain.lastName.length < 60) {
      this.userInfo.lastNameHash = hashEmail(plain.lastName);
    }

    this.updatedAt = Date.now();
    next();
  } catch (error) {
    next(error);
  }
});

// ================= AUTO UPDATE TIMESTAMP =================
BuildingInfoSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// ================= INDEXES (PERFORMANCE BOOST) =================
BuildingInfoSchema.index({ 'userInfo.emailHash': 1 });
BuildingInfoSchema.index({ 'userInfo.firstNameHash': 1 });
BuildingInfoSchema.index({ 'userInfo.lastNameHash': 1 });

// ================= EXPORT =================
export default mongoose.model('BuildingInfo', BuildingInfoSchema, 'leads');
