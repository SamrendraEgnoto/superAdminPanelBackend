import express from 'express';
import { getReports, exportReport } from '../controllers/reportController.js';
import { authenticateJWT } from '../middlewares/auth.js';

const router = express.Router();

router.get('/', authenticateJWT, getReports);
router.get('/export', authenticateJWT, exportReport);

export default router;
