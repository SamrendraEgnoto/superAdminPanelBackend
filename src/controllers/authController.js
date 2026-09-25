import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import SuperAdmin from '../models/SuperAdmin.js';
import Admin from '../models/Admin.js';
import User from '../models/User.js';
import OTP from '../models/Otp.js';
import nodemailer from 'nodemailer';
import { hashEmail, legacyHashEmail } from '../utils/encryption.js';
import { checkEmailExistsAcrossAllRoles } from '../utils/accountUniqueness.js';

// Helper: find a User by email across current and legacy blind indexes as well as plaintext
const findUserByEmail = async (email) => {
  if (!email) return null;
  const normalized = email.toLowerCase().trim();
  const hash = hashEmail(normalized);
  const legacy = legacyHashEmail(normalized);
  const hashes = [hash, legacy].filter(Boolean);
  return await User.findOne({
    $or: [
      { emailHash: { $in: hashes } },
      { email: normalized }
    ]
  });
};

// Helper to find account by email
const findAccountByEmail = async (email) => {
  const normalized = email.toLowerCase();
  const byEmail = await SuperAdmin.findOne({ email: normalized });
  if (byEmail) return byEmail;
  const byHash = await Admin.findOne({ emailHash: hashEmail(normalized) });
  if (byHash) return byHash;
  return findUserByEmail(normalized);
};

// Helper to find account by email and role
const findAccountByEmailAndRole = async (email, role) => {
  const normalized = email.toLowerCase();
  if (role === 'root' || role === 'superadmin') return SuperAdmin.findOne({ email: normalized });
  if (role === 'admin') return Admin.findOne({ emailHash: hashEmail(normalized) });
  return findUserByEmail(normalized);
};

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// =================== MAILER ===================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Helper to send OTP
async function sendOtpEmail(email, otp) {
  await transporter.sendMail({
    from: `"Egnoto App" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is ${otp}. It expires in 10 minutes.`,
  });
}

async function sendPasswordResetEmail(email, otp) {
  await transporter.sendMail({
    from: `"Egnoto App" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Password Reset - OTP Code',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Password Reset Request</h2>
        <p>You requested to reset your password. Use the OTP below:</p>
        <div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 4px; margin: 20px 0;">
          ${otp}
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
        <hr>
        <p style="color: #666; font-size: 12px;">This is an automated email. Please do not reply.</p>
      </div>
    `,
    text: `Your password reset OTP is ${otp}. It expires in 10 minutes. If you didn't request this, ignore this email.`,
  });
}

// Map DB role -> OTP role enum
function toOtpRole(dbRole) {
  const r = String(dbRole || '').toLowerCase();
  if (r === 'root') return 'root';
  if (r === 'delegated' || r === 'superadmin') return 'superadmin';
  if (r === 'admin') return 'admin';
  return 'user';
}

// =================== REGISTER ===================
export async function register(req, res, next) {
  try {
    const { firstName, lastName, email, password, companyName, role } = req.body;

    if (!role) return res.status(400).json({ message: 'Role is required' });

    const normalizedEmail = email.toLowerCase();
    let Model;
    let newUserRole;

    if (role === 'root') {
      Model = SuperAdmin;
      newUserRole = 'root';
    } else if (role === 'superadmin') {
      Model = SuperAdmin;
      newUserRole = 'delegated';
    } else if (role === 'admin') {
      Model = Admin;
      newUserRole = 'admin';
    } else if (role === 'user') {
      Model = User;
      newUserRole = 'user';
    } else {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const uniqueness = await checkEmailExistsAcrossAllRoles(normalizedEmail);
    if (uniqueness.exists) {
      return res.status(409).json({ message: uniqueness.message || 'An account with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    let newUser;
    if (role === 'admin') {
      newUser = new Admin({ firstName, lastName, email: normalizedEmail, password: hashedPassword, companyName });
    } else if (role === 'user') {
      newUser = new User({ firstName, lastName, email: normalizedEmail, password: hashedPassword, role: newUserRole });
    } else {
      newUser = new Model({ firstName, lastName, email: normalizedEmail, password: hashedPassword, role: newUserRole });
    }

    // Generate 6-digit OTP (expires in 10 minutes) and store on the model
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    newUser.emailOTP = otp;
    newUser.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    newUser.isEmailVerified = false;

    // Persist the account BEFORE sending the response
    await newUser.save();

    // Also record in shared otps collection for the verifyOtp flow
    await OTP.create({
      email: normalizedEmail,
      otp,
      role,
      purpose: 'registration'
    });

    await sendOtpEmail(normalizedEmail, otp);

    res.status(201).json({
      success: true,
      message: `${role} registered successfully. Please verify your email with the OTP sent.`
    });

  } catch (err) {
    next(err);
  }
}

// =================== VERIFY OTP =================== 
export async function verifyOtp(req, res, next) {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: 'Email and OTP required' });

    const normalizedEmail = email.toLowerCase();

    // Check shared OTP collection
    const otpRecord = await OTP.findOne({ email: normalizedEmail, otp });
    if (!otpRecord) return res.status(400).json({ message: 'Invalid or expired OTP' });

    if (otpRecord.purpose !== 'registration') {
      return res.status(400).json({ message: 'Invalid OTP purpose' });
    }

    // Find the user model and mark isEmailVerified = true
    let user;
    if (otpRecord.role === 'root' || otpRecord.role === 'superadmin') {
      user = await SuperAdmin.findOne({ email: normalizedEmail });
    } else if (otpRecord.role === 'admin') {
      user = await Admin.findOne({ emailHash: hashEmail(normalizedEmail) });
    } else {
      user = await findUserByEmail(normalizedEmail);
    }

    if (!user) return res.status(404).json({ message: 'User not found' });

    // Verify against the OTP stored on the model, falling back to the shared record
    const storedOtp = user.emailOTP || otpRecord.otp;
    const otpValid = String(storedOtp) === String(otp);
    if (!otpValid) return res.status(400).json({ message: 'Invalid OTP' });

    if (user.otpExpires && user.otpExpires < new Date()) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    if (user.isEmailVerified) return res.status(400).json({ message: 'Email already verified' });

    // Mark email as verified on the user model and clear OTP fields
    user.isEmailVerified = true;
    user.emailOTP = undefined;
    user.otpExpires = undefined;
    await user.save();

    // Optionally remove/clear the used OTP
    otpRecord.verified = true;
    await otpRecord.save();

    const payload = { id: user._id.toString(), role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    res.json({
      success: true,
      message: 'Email verified successfully',
      token,
      role: user.role
    });
  } catch (err) {
    next(err);
  }
}

// ================ RESEND OTP =====================
export async function resendOtp(req, res, next) {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const normalizedEmail = email.toLowerCase();

    // Check for existing user across all roles
    let user = await SuperAdmin.findOne({ email: normalizedEmail });
    if (!user) user = await Admin.findOne({ emailHash: hashEmail(normalizedEmail) });
    if (!user) user = await findUserByEmail(normalizedEmail);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({ message: 'Email already verified' });
    }

    // Generate new 6-digit OTP (expires in 10 minutes) and store on the model
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.emailOTP = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    // Remove any existing OTP for this email and role
    await OTP.deleteMany({ email: normalizedEmail });

    await OTP.create({
      email: normalizedEmail,
      otp,
      role: user.role,
      purpose: 'registration'
    });

    // Resolve the plaintext email for sending (Admin stores it encrypted)
    const recipient = user.getEmail ? user.getEmail() : user.email;
    await sendOtpEmail(recipient || normalizedEmail, otp);

    res.json({ success: true, message: 'OTP resent successfully' });
  } catch (err) {
    next(err);
  }
}

// =================== LOGIN ===================
export async function login(req, res, next) {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role) return res.status(400).json({ message: 'email, password and role required' });

    let user;
    if (role === 'root') {
      user = await SuperAdmin.findOne({ email: email.toLowerCase() });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      if (user.role !== 'root') {
        return res.status(403).json({ message: 'Access denied: Delegated Super Admins cannot log in as Root.' });
      }
    } else if (role === 'superadmin' || role === 'delegated') {
      user = await SuperAdmin.findOne({ email: email.toLowerCase() });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      if (user.role === 'root') {
        return res.status(403).json({ message: 'Please select "Root" role to log in as Root Super Admin.' });
      }
    } else if (role === 'admin') {
      const normEmail = email.toLowerCase();
      user = await Admin.findOne({
        $or: [
          { emailHash: hashEmail(normEmail) },
          { emailHash: legacyHashEmail(normEmail) }
        ]
      });
    } else {
      user = await findUserByEmail(email.toLowerCase());
    }

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // Critical: requires isEmailVerified for all roles
    if (!user.isEmailVerified) return res.status(403).json({ message: 'Email not verified. Please verify your email.' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    // Active check
    if (role === 'admin' && !user.isActive) {
      return res.status(403).json({ message: 'Account is deactivated. Contact Super Admin.' });
    } else if (role === 'user') {
      if (user.isActive === false) {
        return res.status(403).json({ message: 'Your account is deactivated. Contact Admin.' });
      }
      const orgId = user.adminId || user.createdBy;
      if (orgId) {
        const admin = await Admin.findById(orgId);
        if (admin) {
          if (!admin.isActive) return res.status(403).json({ message: 'Organization deactivated. Contact Admin.' });
        } else {
          const sa = await SuperAdmin.findById(orgId);
          if (!sa) return res.status(403).json({ message: 'Organization deactivated. Contact Admin.' });
        }
      }
    }

    const issuedRole = role === 'root' ? 'root' : role;
    const payload = { id: user._id.toString(), role: issuedRole };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

    res.json({ token, role: issuedRole });
  } catch (err) { next(err); }
}

// =================== FORGOT PASSWORD ===================
export async function forgotPassword(req, res, next) {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });
    const normalizedEmail = email.toLowerCase().trim();

    const user = await findAccountByEmail(normalizedEmail);

    // Always return generic success to prevent email enumeration
    if (!user) {
      return res.json({ success: true, message: 'If an account exists for this email, an OTP has been sent.' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpRole = toOtpRole(user.role);

    // Remove any existing password-reset OTPs for this email
    await OTP.deleteMany({ email: normalizedEmail, purpose: 'password-reset' });

    await OTP.create({
      email: normalizedEmail,
      otp,
      role: otpRole,
      purpose: 'password-reset'
    });

    try {
      user.emailOTP = otp;
      user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
      await user.save();
    } catch (_) {
      // non-critical
    }

    const recipient = user.getEmail ? user.getEmail() : user.email;
    const targetEmail = recipient && !recipient.includes('[encrypted]') ? recipient : normalizedEmail;

    console.log(`[DEV] Password reset OTP for ${normalizedEmail} (${otpRole}): ${otp} -> ${targetEmail}`);

    try {
      await sendPasswordResetEmail(targetEmail, otp);
      console.log(`[MAIL] Password reset email sent to ${targetEmail}`);
    } catch (mailErr) {
      console.error('Failed to send password reset email:', mailErr.message || mailErr);
      console.error(`[DEV FALLBACK] OTP for ${targetEmail} is ${otp} (use this to test reset)`);
      try { await sendOtpEmail(targetEmail, otp); } catch (_) {}
    }

    res.json({ success: true, message: 'If an account exists for this email, an OTP has been sent.' });
  } catch (err) {
    next(err);
  }
}

// =================== RESET PASSWORD ===================
export async function resetPassword(req, res, next) {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'Email, OTP and new password are required' });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const otpStr = String(otp).trim();

    const otpRecord = await OTP.findOne({ email: normalizedEmail, otp: otpStr, purpose: 'password-reset' });
    if (!otpRecord) {
      return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    if (otpRecord.attempts >= 5) {
      await OTP.deleteMany({ email: normalizedEmail, purpose: 'password-reset' });
      return res.status(429).json({ message: 'Too many failed attempts. Please request a new OTP.' });
    }

    // Find user account (cross-model)
    let user = await SuperAdmin.findOne({ email: normalizedEmail });
    if (!user) user = await Admin.findOne({ emailHash: hashEmail(normalizedEmail) });
    if (!user) user = await findUserByEmail(normalizedEmail);

    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.emailOTP && String(user.emailOTP) !== otpStr) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: 'Invalid OTP' });
    }
    if (user.otpExpires && user.otpExpires < new Date()) {
      await OTP.deleteMany({ email: normalizedEmail, purpose: 'password-reset' });
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    // Set plaintext password — model pre-save hook hashes it.
    user.password = String(newPassword);
    user.emailOTP = undefined;
    user.otpExpires = undefined;
    await user.save();

    await OTP.deleteMany({ email: normalizedEmail, purpose: 'password-reset' });

    res.json({ success: true, message: 'Password reset successfully. Please login with your new password.' });
  } catch (err) {
    next(err);
  }
}

// *****************API for upload************
export async function uploadAvatar(req, res, next) {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    
    // Update the user's avatar in the database — handle all roles incl. root/delegated
    let Model;
    const role = String(req.user.role || '').toLowerCase();
    if (role === 'root' || role === 'superadmin' || role === 'delegated') Model = SuperAdmin;
    else if (role === 'admin') Model = Admin;
    else Model = User;

    const updated = await Model.findByIdAndUpdate(req.user.id, { avatar: avatarUrl }, { new: true });
    if (!updated) return res.status(404).json({ message: 'User not found' });

    res.json({ success: true, url: avatarUrl });
  } catch (err) {
    next(err);
  }
}
