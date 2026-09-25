import express from 'express';
import * as superAdminCtrl from '../controllers/superAdminController.js';
import * as leadShareCtrl from '../controllers/leadShareController.js';
import { authenticateJWT } from '../middlewares/auth.js';
import { allowRoles, requireRoot } from '../middlewares/roles.js';

// ############### code for super admin #########
// Superadmin routes to manage admins

const router = express.Router();

router.use(authenticateJWT, allowRoles(['superadmin']));

router.get('/profile', superAdminCtrl.getProfile);
router.put('/profile', superAdminCtrl.updateProfile);

router.get('/admins', superAdminCtrl.listAdmins);
router.get('/dashboard/stats', superAdminCtrl.getDashboardStats);
router.get('/admins/:id', superAdminCtrl.getAdmin);
router.post('/admins', superAdminCtrl.createAdmin);
router.put('/admins/:id', superAdminCtrl.updateAdmin);
router.put('/admins/:id/retry-provision', superAdminCtrl.retryProvision);
router.put('/admins/:id/plan', superAdminCtrl.updateAdminPlan);
router.put('/admins/:id/status', superAdminCtrl.toggleAdminStatus);
router.delete('/admins/:id', superAdminCtrl.deleteAdmin);
router.get('/admins/:id/embed-keys', superAdminCtrl.listAdminEmbedKeys);
router.post('/admins/:id/embed-keys', superAdminCtrl.generateEmbedKey);
router.post('/admins/:id/embed-keys/:key/rotate', superAdminCtrl.rotateEmbedKey);
router.delete('/admins/:id/embed-keys/:key/revoke', superAdminCtrl.revokeAdminEmbedKey);

// ===== Delegated Super Admin management (root-only) =====
// Distinct from /admins (which manages businesses). Only the root Super Admin
// may create or manage other Super Admins; a delegated SA is blocked here.
router.get('/superadmins', requireRoot, superAdminCtrl.listSuperAdmins);
router.get('/superadmins/:id', requireRoot, superAdminCtrl.getSuperAdmin);
router.post('/superadmins', requireRoot, superAdminCtrl.createSuperAdmin);
router.put('/superadmins/:id', requireRoot, superAdminCtrl.updateSuperAdmin);
router.delete('/superadmins/:id', requireRoot, superAdminCtrl.deleteSuperAdmin);

// ===== DSA Personal Embed Keys =====
// Delegated Super Admins embed the 3D Estimator on THEIR OWN website.
// Keys live on the SuperAdmin model — NOT on an Admin document.
router.get('/my-embed-keys', superAdminCtrl.listMyEmbedKeys);
router.post('/my-embed-keys', superAdminCtrl.generateMyEmbedKey);
router.post('/my-embed-keys/:key/rotate', superAdminCtrl.rotateMyEmbedKey);
router.delete('/my-embed-keys/:key/revoke', superAdminCtrl.revokeMyEmbedKey);

// ===== DSA Lead Management & Sharing =====
// DSA views their own leads (from their embed key) and shares subsets to
// data-viewer Admins they created.
router.get('/leads', leadShareCtrl.getDsaLeads);
router.post('/leads/share', leadShareCtrl.shareLead);
router.delete('/leads/:id/share/:adminId', leadShareCtrl.unshareLead);

// ===== DSA User Management =====
// A DSA can view and manage all users belonging to admins THEY created.
// This mirrors what the admin-level panel does but scoped to the DSA's branch.
router.get('/users', superAdminCtrl.getDsaUsers);
router.post('/users', superAdminCtrl.createDsaUser);
router.put('/users/:id', superAdminCtrl.updateDsaUser);
router.delete('/users/:id', superAdminCtrl.deleteDsaUser);

export default router;

