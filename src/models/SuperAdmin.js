import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { hashEmail } from '../utils/encryption.js';

const SuperAdminSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String },
  email: { type: String, required: true, unique: true, lowercase: true },
  emailHash: { type: String, index: true },
  password: { type: String, required: true },
  avatar: { type: String, default: '' },
  phone: { type: String, default: '' },
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
  role: { type: String, enum: ['root', 'delegated'], default: 'delegated' },

  // createdById references the root SuperAdmin; null for root itself
  createdById: { type: mongoose.Schema.Types.ObjectId, ref: 'SuperAdmin' },

  // ===== OTP Email Verification =====
  isEmailVerified: { type: Boolean, default: false },
  emailOTP: { type: String },
  otpExpires: { type: Date },

  // ===== Embed Key Support (Delegated SA only) =====
  // Delegated Super Admins embed the 3D Estimator on their OWN website.
  // Their embed keys live here — NOT on an Admin document.
  subdomain: { type: String, unique: true, sparse: true },
  embedKeys: [{
    key: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    revokedAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null }, // grace period on rotation
    scope: { type: String, default: 'create-lead-only' },
    lastUsedAt: { type: Date, default: null },
    lastUsedOrigin: { type: String, default: null }
  }],

  // ===== Encryption (Delegated SA — for leads from their own embed) =====
  // Per-tenant DEK wrapped under the platform KEK. Unlocked by the DSA's
  // passkey session; leads coming through the DSA's embed key are encrypted
  // with this DEK so only the DSA (and Root) can decrypt them.
  wrappedDataKey: { type: String, sparse: true },
  wrappedDataKeyKMS: { type: String, sparse: true },
  kmsKeyRef: { type: String, unique: true, sparse: true },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Backward compat: old docs had location as string → convert to object
SuperAdminSchema.pre('init', function(doc) {
  if (typeof doc.location === 'string') {
    doc.location = { street: doc.location, city: '', state: '', country: '', zipCode: '' };
  }
});

SuperAdminSchema.pre('save', async function (next) {
  // Normalize location if sent as string (e.g. legacy form)
  if (typeof this.location === 'string') {
    this.location = { street: this.location, city: '', state: '', country: '', zipCode: '' };
  }
  if (this.email && (this.isModified('email') || !this.emailHash)) {
    this.email = this.email.toLowerCase().trim();
    this.emailHash = hashEmail(this.email);
  }
  if (!this.isModified('password')) return next();
  // Prevent double-hashing when controller already hashed (e.g. password reset)
  if (this.password && this.password.startsWith('$2')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

SuperAdminSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

export default mongoose.model('SuperAdmin', SuperAdminSchema);
