import express from 'express';
import { requireCustomerToken } from '../middlewares/customerTokenAuth.js';
import {
  getCustomerLead,
  eraseCustomerLead,
  correctCustomerLead
} from '../controllers/customerRightsController.js';

// Public (no admin-auth) customer-rights router. Auth is a lead-scoped JWT
// passed as ?token=<quoteToken>, embedded in the original quote email link.
const router = express.Router();

router.get('/:leadId/export', requireCustomerToken, getCustomerLead);
router.post('/:leadId/erase', requireCustomerToken, eraseCustomerLead);
router.post('/:leadId/correct', requireCustomerToken, correctCustomerLead);

export default router;