import express from 'express';
import * as userCtrl from '../controllers/userController.js';
import { authenticateJWT } from '../middlewares/auth.js';
import { allowRoles } from '../middlewares/roles.js';
import { tenantPasskeyContext } from '../middlewares/tenantPasskeyContext.js';

const router = express.Router();

// Tenant passkey from header -> in-memory session (used by User/BuildingInfo
// pre('save') hooks to unwrap the tenant DEK). No-op when no header is sent.
router.use(tenantPasskeyContext);

// ================= ADMIN ACCESS =================

// Admin can create users
router.post(
  '/',
  authenticateJWT,
  allowRoles(['admin', 'superadmin']),
  userCtrl.createUser
);

// Admin can view all users
router.get(
  '/',
  authenticateJWT,
  allowRoles(['admin', 'superadmin']),
  userCtrl.getAllUsers
);

router.post(
  '/',
  authenticateJWT,
  allowRoles(['admin', 'superadmin']),
  userCtrl.createUser
);
// ================= USER SELF ACCESS =================

// Profile
router.get('/me', authenticateJWT, allowRoles(['user']), userCtrl.getProfile);
router.put('/me', authenticateJWT, allowRoles(['user']), userCtrl.updateProfile);
router.get('/dashboard', authenticateJWT, allowRoles(['user']), userCtrl.getDashboard);

// Team (optional, if user manages sub-users)
router.get('/team', authenticateJWT, allowRoles(['user']), userCtrl.getTeamMembers);
router.post('/team', authenticateJWT, allowRoles(['user']), userCtrl.createTeamMember);
router.put('/team/:id', authenticateJWT, allowRoles(['user']), userCtrl.updateTeamMember);
router.delete('/team/:id', authenticateJWT, allowRoles(['user']), userCtrl.deleteTeamMember);

// ================= USER LEADS =================

router.get('/buildings', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.listMyBuildings);
router.get('/buildings/:id', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.getMyBuilding);
router.post('/buildings', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.createMyBuilding);
router.put('/buildings/:id', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.updateMyBuilding);
router.delete('/buildings/:id', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.deleteMyBuilding);

// Lead transfer
router.post('/buildings/:id/transfer', authenticateJWT, allowRoles(['user', 'admin', 'superadmin']), userCtrl.transferLead);

router.post(
  '/:userId/assign-leads',
  authenticateJWT,
  allowRoles(['admin', 'superadmin']),
  userCtrl.assignLeadsToUser
);

export default router;