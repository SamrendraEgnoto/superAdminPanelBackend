import express from 'express';
import { body } from 'express-validator';
import { handleValidation } from '../utils/validators.js';
import { login, register, verifyOtp, resendOtp, forgotPassword, resetPassword, uploadAvatar } from '../controllers/authController.js';
import { updateProfile } from '../controllers/userController.js';
import { authenticateJWT } from '../middlewares/auth.js';
import { upload } from '../middlewares/upload.js';
import { configureTenantPasskey } from '../controllers/onboardingController.js';
const router = express.Router();

// Login & Register
router.post('/login', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('role').customSanitizer(v => (v || '').toString().toLowerCase()).isIn(['root','superadmin','admin','user']),
  handleValidation
], login);

router.post('/register', [
  body('firstName').notEmpty(),
  body('lastName').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('role').customSanitizer(v => (v || '').toString().toLowerCase()).isIn(['root','superadmin','admin','user']),
  handleValidation
], register);

router.post('/verify-otp', [
  body('email')
    .exists().withMessage('Email is required')
    .bail()
    .isEmail().withMessage('Valid email is required')
    .bail()
    .customSanitizer(v => v?.toLowerCase()),

  body('otp')
    .exists().withMessage('OTP is required')
    .bail()
    .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
    .bail()
    .customSanitizer(v => v?.toString()),
  handleValidation
], verifyOtp);


router.post('/resend-otp', [
  body('email')
    .exists().withMessage('Email is required')
    .bail()
    .isEmail().withMessage('Valid email is required')
    .bail()
    .customSanitizer(v => v?.toLowerCase()),

  handleValidation
], resendOtp);

router.post('/forgot-password', [
  body('email')
    .exists().withMessage('Email is required')
    .bail()
    .isEmail().withMessage('Valid email is required')
    .bail()
    .customSanitizer(v => v?.toLowerCase().trim()),
  handleValidation
], forgotPassword);

router.post('/reset-password', [
  body('email')
    .exists().withMessage('Email is required')
    .bail()
    .isEmail().withMessage('Valid email is required')
    .bail()
    .customSanitizer(v => v?.toLowerCase().trim()),
  body('otp')
    .exists().withMessage('OTP is required')
    .bail()
    .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
    .bail()
    .customSanitizer(v => v?.toString().trim()),
  body('newPassword')
    .exists().withMessage('New password is required')
    .bail()
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  handleValidation
], resetPassword);

// Profile Management
router.put('/profile', authenticateJWT, updateProfile);
router.post('/upload-avatar', authenticateJWT, upload.single('avatar'), uploadAvatar);

// Envelope-encryption onboarding: sender email + passkey -> tenant DEK
router.post('/onboarding/tenant', authenticateJWT, configureTenantPasskey);

export default router;
