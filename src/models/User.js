import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { encryptField, decryptField, hashEmail } from '../utils/encryption.js';
import { getTenantDEK, ensureTenantDEK } from '../services/tenantCrypto.js';

const UserSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String },
  email: { type: String, required: true },
  emailHash: { type: String, index: true },
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
  role: { type: String, default: 'user' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  parentUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  parentUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  // ===== OTP Email Verification =====
  isEmailVerified: { type: Boolean, default: false },
  emailOTP: { type: String },
  otpExpires: { type: Date },
  permissions: {
    canCreateLead: { type: Boolean, default: false },
    canCreateSubUsers: { type: Boolean, default: false },
    canTransferLeads: { type: Boolean, default: false },
    canShareLeads: { type: Boolean, default: false }
  },
  isActive: { type: Boolean, default: true },
  status: { type: String, default: 'active' },
});

// Backward compat: old string location → object
UserSchema.pre('init', function(doc) {
  if (typeof doc.location === 'string') {
    doc.location = { street: doc.location, city: '', state: '', country: '', zipCode: '' };
  }
});
UserSchema.pre('save', function (next) {
  if (typeof this.location === 'string') {
    this.location = { street: this.location, city: '', state: '', country: '', zipCode: '' };
  }
  next();
});

UserSchema.pre('save', async function (next) {
  if (this.isModified('password') && this.password && !this.password.startsWith('$2')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Envelope-encryption hook: when the tenant DEK is resolvable (passkey present
// in the request context / session), encrypt PII with the tenant DEK. Always
// maintains a stable emailHash on the PLAINTEXT so hash-first lookups (login,
// OTP) keep working even after encryption.
UserSchema.pre('save', async function (next) {
  try {
    const adminIdStr = this.adminId ? this.adminId.toString() : (this.createdBy ? this.createdBy.toString() : '');
    const dek = adminIdStr ? await ensureTenantDEK(adminIdStr) : null;

    const modified = this.isNew
      || this.isModified('email')
      || this.isModified('phone')
      || this.isModified('firstName')
      || this.isModified('lastName');

    if (modified && this.email) {
      if (!this.emailHash || this.isModified('email')) {
        this.emailHash = hashEmail(this.email);
      }
      if (dek) {
        const enc = encryptField(this.email, dek);
        if (enc) this.email = enc;
        if (this.phone) {
          const p = encryptField(this.phone, dek);
          if (p) this.phone = p;
        }
        if (this.firstName) {
          const f = encryptField(this.firstName, dek);
          if (f) this.firstName = f;
        }
        if (this.lastName) {
          const l = encryptField(this.lastName, dek);
          if (l) this.lastName = l;
        }
      }
    }

    next();
  } catch (error) {
    next(error);
  }
});

// ===== Decrypting getters (envelope-encryption path aware) =====
const getAdminIdString = (doc) => {
  try {
    const a = doc.adminId || doc.createdBy;
    if (!a) return '';
    if (typeof a === 'object' && a._id) return a._id.toString();
    return a.toString();
  } catch {
    return '';
  }
};

const resolveFieldDecrypted = (val, adminId) => {
  if (!val) return '';
  if (typeof val === 'string' && val.includes('@')) return val;

  const dek = adminId ? getTenantDEK(adminId) : null;
  if (dek) {
    const decrypted = decryptField(val, dek);
    if (decrypted) return decrypted;
  }

  const legacy = decryptField(val);
  if (legacy) return legacy;

  if (typeof val === 'string' && val.length > 0 && !val.startsWith('gcm:') && !val.startsWith('{') && !/^[A-Za-z0-9+/=]{40,}$/.test(val)) {
    return val;
  }
  return '';
};

UserSchema.methods.getEmail = function () {
  if (this.email) {
    const adminId = getAdminIdString(this);
    const d = resolveFieldDecrypted(this.email, adminId);
    if (d) return d;
    return this.email;
  }
  return '';
};

UserSchema.methods.getPhone = function () {
  if (this.phone) {
    const adminId = getAdminIdString(this);
    const d = resolveFieldDecrypted(this.phone, adminId);
    if (d) return d;
    return this.phone;
  }
  return '';
};

UserSchema.methods.getFirstName = function () {
  if (this.firstName) {
    const adminId = getAdminIdString(this);
    const d = resolveFieldDecrypted(this.firstName, adminId);
    if (d) return d;
    return this.firstName;
  }
  return '';
};

UserSchema.methods.getLastName = function () {
  if (this.lastName) {
    const adminId = getAdminIdString(this);
    const d = resolveFieldDecrypted(this.lastName, adminId);
    if (d) return d;
    return this.lastName;
  }
  return '';
};

const transformUser = (doc, ret) => {
  const email = doc.getEmail ? doc.getEmail() : ret.email;
  const phone = doc.getPhone ? doc.getPhone() : ret.phone;
  const firstName = doc.getFirstName ? doc.getFirstName() : ret.firstName;
  const lastName = doc.getLastName ? doc.getLastName() : ret.lastName;

  ret.email = email;
  ret.phone = phone;
  ret.firstName = firstName;
  ret.lastName = lastName;
  delete ret.password;
  delete ret.emailHash;
  return ret;
};

UserSchema.set('toJSON', { transform: transformUser });
UserSchema.set('toObject', { transform: transformUser });

UserSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

export default mongoose.model('User', UserSchema);
