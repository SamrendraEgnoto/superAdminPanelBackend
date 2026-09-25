import express from 'express';
import * as adminCtrl from '../controllers/adminController.js';
import { getSharedLeads } from '../controllers/leadShareController.js';
import { authenticateJWT } from '../middlewares/auth.js';
import { allowRoles } from '../middlewares/roles.js';
import { tenantPasskeyContext } from '../middlewares/tenantPasskeyContext.js';

const router = express.Router();

// Allow admin and superadmin to access; carry tenant passkey into the session
router.use(authenticateJWT, tenantPasskeyContext, allowRoles(['admin', 'superadmin']));

// Profile management
router.get('/profile', adminCtrl.getProfile);
router.put('/profile', adminCtrl.updateProfile);

// Dashboard
router.get('/dashboard', adminCtrl.getDashboard);

// User management
router.get('/users', adminCtrl.listUsers);
router.get('/users/:id', adminCtrl.getUser);
router.post('/users', adminCtrl.createUser);
router.put('/users/:id', adminCtrl.updateUser);
router.delete('/users/:id', adminCtrl.deleteUser);

// User buildings
router.get('/users/:id/buildings', adminCtrl.getUserBuildings);

// Lead assignments (multi-user & permission)
router.post('/assign-leads', adminCtrl.adminAssignUsersToLeads);
router.put('/update-permission', adminCtrl.updateUserPermission);

// Domain verification
router.post('/verify-domain', adminCtrl.verifyDomain);
router.post('/check-domain', adminCtrl.checkDomain);
router.post('/sync-domain', adminCtrl.syncDomainToEstimator);
router.post('/export-lead/:leadId', adminCtrl.exportLead);
router.post('/erase-lead/:leadId', adminCtrl.eraseLead);
router.get('/leads/export', adminCtrl.exportAllLeads);
router.get('/leads/erase', adminCtrl.eraseAllLeads);
router.post('/test-email', adminCtrl.testEmail);

// ===== Data-Viewer Admin: Shared Leads =====
// Data-viewer Admins (created by DSA) can only see leads the DSA shared with them.
// Full tenant Admins (created by Root) use the standard /buildings endpoint.
router.get('/shared-leads', getSharedLeads);

// ===== Tenant Admin Embed Keys (Admin created by Root) =====
router.get('/my-embed-keys', adminCtrl.listMyEmbedKeys);
router.post('/my-embed-keys', adminCtrl.generateMyEmbedKey);
router.post('/my-embed-keys/:key/rotate', adminCtrl.rotateMyEmbedKey);
router.delete('/my-embed-keys/:key/revoke', adminCtrl.revokeMyEmbedKey);

export default router;


