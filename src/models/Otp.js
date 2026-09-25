import mongoose from 'mongoose';

const OTPSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true, 
    lowercase: true 
  },
  otp: { 
    type: String, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ['root', 'superadmin', 'admin', 'user'], 
    required: true 
  },
  purpose: {
    type: String,
    enum: ['registration', 'password-reset', 'email-verification'],
    default: 'registration'
  },
  userData: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  verified: { 
    type: Boolean, 
    default: false 
  },
  attempts: { 
    type: Number, 
    default: 0 
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    expires: 600 // 10 minutes
  }
});

OTPSchema.index({ email: 1, role: 1 });

export default mongoose.model('OTP', OTPSchema);
