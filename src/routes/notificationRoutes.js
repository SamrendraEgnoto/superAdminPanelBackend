import express from 'express';
import {
  getNotifications,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  clearAllNotifications
} from '../controllers/notificationController.js';
import { authenticateJWT } from '../middlewares/auth.js';

const router = express.Router();

// All notification routes require JWT authentication
router.use(authenticateJWT);

router.get('/', getNotifications);
router.patch('/read-all', markAllAsRead);
router.patch('/:id/read', markAsRead);
router.delete('/clear-all', clearAllNotifications);
router.delete('/:id', deleteNotification);
router.delete('/', clearAllNotifications);

export default router;
