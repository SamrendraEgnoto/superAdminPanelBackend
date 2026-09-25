import express from 'express';
import * as bridgeCtrl from '../controllers/bridgeController.js';
import { authenticateJWT } from '../middlewares/auth.js';
import embedKeyAuth from '../middlewares/embedKeyAuth.js';
import enforceHTTPS from '../utils/enforceHTTPS.js';

const router = express.Router();

router.use(enforceHTTPS);

// Embed-key-authenticated route (no JWT). Declared BEFORE authenticateJWT so it
// bypasses the tenant JWT requirement while still being fully authenticated via
// the resolve-able embed key.
router.post('/embed/leads', embedKeyAuth, bridgeCtrl.submitLeadFromEmbed);

router.use(authenticateJWT);

router.post('/leads', bridgeCtrl.submitLeadFromEstimator);

export default router;
