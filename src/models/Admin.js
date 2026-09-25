import mongoose from 'mongoose';
import { createHash } from 'crypto';
import bcrypt from 'bcryptjs';
import { encryptField, decryptField, hashEmail } from '../utils/encryption.js';
import { getTenantDEK } from '../services/tenantCrypto.js';

// Helper: get admin ID string for encryption key derivation
const getAdminIdString = (doc) => {
  try {
    return doc._id ? doc._id.toString() : '';
  } catch {
    return '';
  }
};

// ================= SCHEMA DEFINITION =================
const AdminSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  avatar: { type: String, default: '' },
  department: { type: String, default: '' },
  bio: { type: String, default: '' },
  location: {
    street: { type: String, default: '' },
    city: { type: String, default: '' },
    state: { type: String, default: '' },
    country: { type: String, default: '' },
    zipCode: { type: String, default: '' }
  },
  website: { type: String, default: '' },
  password: { type: String, required: true },
  companyName: { type: String },
  plan: { type: String, default: 'free' },
  userLimit: { type: Number, default: 5 },
  createdById: { type: mongoose.Schema.Types.ObjectId, ref: 'SuperAdmin' },
  isActive: { type: Boolean, default: true },
  emailHash: { type: String, index: true },
  isEmailVerified: { type: Boolean, default: false },
  emailOTP: { type: String },
  otpExpires: { type: Date },
  wrappedDataKey: { type: String, sparse: true },
  wrappedDataKeyKMS: { type: String, sparse: true },
  kmsKeyRef: { type: String, unique: true, sparse: true },
  smtpSenderEmail: { type: String, sparse: true },
  onboardingCompleted: { type: Boolean, default: false },
  role: { type: String, default: 'admin' },
  subdomain: { type: String, unique: true, sparse: true },
  customDomain: { type: String, unique: true, sparse: true },
  domainVerified: { type: Boolean, default: false },
  domainVerificationToken: { type: String },
  estimatorProvisioned: { type: Boolean, default: false },
  totalLeads: { type: Number, default: 0 },
  retentionDays: { type: Number, default: 90 },
  marketingConsent: { type: Boolean, default: false },

  // ===== Admin Type =====
  // 'tenant'      = created by Root — full tenant, gets embed key, subdomain, bridge sync
  // 'data-viewer' = created by Delegated SA — data only, no embed key, no subdomain, no bridge sync
  adminType: { type: String, enum: ['tenant', 'data-viewer'], default: 'tenant' },

  // Embed keys used by the 3D Estimator to act on behalf of this tenant
  // (scope 'create-lead-only'). Keys are prefixed with the admin's subdomain.
  // NOTE: Only populated for adminType === 'tenant'. Data-viewers have no embed keys.
  embedKeys: [{
    key: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    revokedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null }, // grace period on rotation
    scope: { type: String, default: 'create-lead-only' },
    lastUsedAt: { type: Date, default: null },
    lastUsedOrigin: { type: String, default: null }
  }],

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  permissions: {
    canCreateLead: { type: Boolean, default: true },
    canCreateSubUsers: { type: Boolean, default: false },
    canTransferLeads: { type: Boolean, default: false },
    canShareLeads: { type: Boolean, default: false }
  }
});

// Helper instance method to get decrypted email
// NOTE: must stay SYNCHRONOUS because toJSON() cannot await. The previous
// implementation called the async decryptFieldWithKMS without awaiting, which
// returned a Promise that serialized to `{}` and crashed React renders.
AdminSchema.methods.getEmail = function () {
  if (this.email) {
    const email = this.email;
    if (typeof email === 'string' && email.length > 20) {
      // New envelope-encryption path: unwrap per-tenant DEK (passkey session).
      const dek = getTenantDEK(this._id ? this._id.toString() : '', this.wrappedDataKey);
      if (dek) {
        const decrypted = decryptField(email, dek);
        if (decrypted) return decrypted;
      }
      // Legacy data encrypted with the master key (pre-envelope) still works.
      const legacy = decryptField(email);
      if (legacy) return legacy;
      return '[encrypted]';
    }
    return this.email;
  }
  return '';
};

// Helper instance method to get decrypted phone
AdminSchema.methods.getPhone = function () {
  if (this.phone) {
    const phone = this.phone;
    if (typeof phone === 'string' && (phone.startsWith('gcm:') || phone.length > 20)) {
      const dek = getTenantDEK(this._id ? this._id.toString() : '', this.wrappedDataKey);
      if (dek) {
        const decrypted = decryptField(phone, dek);
        if (decrypted) return decrypted;
      }
      const legacy = decryptField(phone);
      if (legacy) return legacy;
      return this.phone;
    }
    return this.phone;
  }
  return '';
};

// Override toJSON to return decrypted data
AdminSchema.methods.toJSON = function () {
  const obj = this.toObject();
  obj.email = this.getEmail();
  obj.phone = this.getPhone();
  delete obj.password;
  delete obj.emailOTP;
  delete obj.otpExpires;
  delete obj.emailHash;
  return obj;
};

AdminSchema.set('toJSON', {
  transform: function (doc, ret) {
    if (doc.getEmail) ret.email = doc.getEmail();
    if (doc.getPhone) ret.phone = doc.getPhone();
    delete ret.password;
    delete ret.emailOTP;
    delete ret.otpExpires;
    delete ret.emailHash;
    return ret;
  }
});

AdminSchema.set('toObject', {
  transform: function (doc, ret) {
    if (doc.getEmail) ret.email = doc.getEmail();
    if (doc.getPhone) ret.phone = doc.getPhone();
    delete ret.password;
    delete ret.emailOTP;
    delete ret.otpExpires;
    delete ret.emailHash;
    return ret;
  }
});

// Backward compat: old string location → object
AdminSchema.pre('init', function(doc) {
  if (typeof doc.location === 'string') {
    doc.location = { street: doc.location, city: '', state: '', country: '', zipCode: '' };
  }
});

AdminSchema.pre('save', function (next) {
  if (typeof this.location === 'string') {
    this.location = { street: this.location, city: '', state: '', country: '', zipCode: '' };
  }
  next();
});

// ================= ENCRYPTION HOOK: encrypt PII using the tenant DEK =================
AdminSchema.pre('save', async function (next) {
  try {
    const adminIdString = getAdminIdString(this);

    // Resolve the tenant DEK from the in-memory passkey session (if any). When
    // no DEK is resolvable (e.g. pre-onboarding), fall back to the legacy
    // master-key keying so old behaviour / old data stays intact.
    const dek = getTenantDEK(adminIdString, this.wrappedDataKey) || undefined;

    // Encrypt + hash email ONLY when it actually changed. Re-running encryption
    // on every save would double-encrypt the value and corrupt the stable
    // emailHash used for lookups (e.g. during OTP verification / profile update).
    if (this.isModified('email') && this.email) {
      // Normalize here (the schema can't lowercase the field any more because
      // the stored value is base64 ciphertext, not a readable email).
      const plaintextEmail = String(this.email).toLowerCase().trim();
      const encrypted = encryptField(plaintextEmail, dek);
      if (encrypted) this.email = encrypted;
      this.emailHash = hashEmail(plaintextEmail);
    }

    if (this.isModified('phone') && this.phone) {
      const encrypted = encryptField(this.phone, dek);
      if (encrypted) this.phone = encrypted;
    }

    // Rotate/wrap data key on first save (admin creation) if kmsKeyRef not set
    if (!this.kmsKeyRef && this.isNew) {
      // In production, this would call KMS to generate a per-tenant data key
      // and wrap it, storing the reference in kmsKeyRef
      // For now, simulate with a deterministic derivation from admin._id
      const dataKeyId = createHash('sha256').update(String(this._id)).digest('hex').substring(0, 32);
      this.kmsKeyRef = dataKeyId;
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Hash the password on save when it is modified and not already a bcrypt hash.
// This guarantees Admins created by a Super Admin (or via self-registration)
// can actually authenticate at login.
AdminSchema.pre('save', async function (next) {
  if (this.isModified('password') && this.password && !this.password.startsWith('$2')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// ================= ADD: Wrapped Data Key Reference =================
AdminSchema.add({
  wrappedDataKey: {
    type: String,
    sparse: true
  }
});

// ================= INDEXES =================
AdminSchema.index({ emailHash: 1 });
AdminSchema.index({ 'embedKeys.key': 1 }, { unique: true, sparse: true });

// ================= PASSWORD COMPARE =================
AdminSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// ================= TOTAL LEADS COUNTER =================
// Atomic counters so concurrent lead intake can never lose updates (no
// read-modify-write). The increment uses a plain $inc; the decrement clamps at
// 0 via an aggregation-pipeline $max so the count can never go negative.
AdminSchema.statics.incrementTotalLeads = function (adminId) {
  if (!adminId) return Promise.resolve({ matchedCount: 0 });
  return this.findByIdAndUpdate(adminId, { $inc: { totalLeads: 1 } });
};

AdminSchema.statics.decrementTotalLeads = function (adminId, count = 1) {
  if (!adminId || !Number.isFinite(count) || count <= 0) {
    return Promise.resolve({ matchedCount: 0 });
  }
  return this.updateOne(
    { _id: adminId },
    [{ $set: { totalLeads: { $max: [{ $subtract: ['$totalLeads', count] }, 0] } } }]
  );
};

// ================= EXPORT =================
export default mongoose.model('Admin', AdminSchema);
