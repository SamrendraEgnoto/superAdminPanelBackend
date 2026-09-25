import express from 'express';
import { getSettings, updateSettings } from '../controllers/settingsController.js';
import { authenticateJWT } from '../middlewares/auth.js';

const router = express.Router();

// Apply protection middleware to all settings routes
router.use(authenticateJWT);

router.get('/', getSettings);
router.put('/', updateSettings);

export default router;
