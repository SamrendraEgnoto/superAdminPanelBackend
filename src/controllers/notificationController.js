import mongoose from 'mongoose';
import Notification from '../models/Notification.js';
import { decryptField } from '../utils/encryption.js';

/**
 * Get all notifications for the current authenticated user
 */
export async function getNotifications(req, res, next) {
  try {
    const userId = req.user.id;
    const role = req.user.role;
    const dbRole = req.user.dbRole;
    const isRoot = role === 'root' || dbRole === 'root';

    let userObjId = null;
    try {
      userObjId = new mongoose.Types.ObjectId(userId);
    } catch (e) {}

    let query;
    if (isRoot) {
      // Root Super Admin manages the SaaS platform, NEVER individual tenant leads.
      // Strictly exclude any notifications where entityType === 'lead' or title has 'lead'
      query = {
        $and: [
          {
            $or: [
              { recipient: userId },
              ...(userObjId ? [{ recipient: userObjId }] : []),
              { recipientRole: 'root' },
              { recipientRole: 'superadmin' },
              { recipientRole: 'all' }
            ]
          },
          { entityType: { $ne: 'lead' } },
          { title: { $not: /lead/i } }
        ]
      };
    } else {
      const conditions = [
        { recipient: userId },
        ...(userObjId ? [{ recipient: userObjId }] : [])
      ];
      if (role) conditions.push({ recipientRole: role });
      if (dbRole && dbRole !== role) conditions.push({ recipientRole: dbRole });
      conditions.push({ recipientRole: 'all' });
      query = { $or: conditions };
    }

    console.log(`[Notification Poll] User: ${req.user.email} (id: ${userId}, role: ${role}, dbRole: ${dbRole}, isRoot: ${isRoot})`);

    const [notifications, unreadCount] = await Promise.all([
      Notification.find(query)
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      Notification.countDocuments({ ...query, read: false })
    ]);

    // Format for client with decrypted fields (plain text for UI)
    const formatted = notifications
      .map(n => ({
        id: n._id.toString(),
        title: decryptField(n.title) || n.title,
        message: decryptField(n.message) || n.message,
        type: n.type || 'info',
        entityType: n.entityType || 'lead',
        entityId: n.entityId || null,
        link: n.link || (n.entityType === 'lead' && n.entityId ? `/leads/${n.entityId}` : null),
        read: !!n.read,
        createdAt: n.createdAt
      }))
      .filter(n => {
        if (isRoot && (n.entityType === 'lead' || /lead/i.test(n.title) || /lead/i.test(n.message))) {
          return false;
        }
        return true;
      });

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');

    return res.json({
      success: true,
      data: formatted,
      unreadCount
    });
  } catch (err) {
    console.error('getNotifications error:', err);
    next(err);
  }
}

/**
 * Mark a single notification as read
 */
export async function markAsRead(req, res, next) {
  try {
    const { id } = req.params;
    const notif = await Notification.findByIdAndUpdate(
      id,
      { read: true, readAt: new Date() },
      { new: true }
    );
    if (!notif) {
      return res.status(404).json({ success: false, message: 'Notification not found' });
    }
    const safeData = notif.toObject();
    safeData.title = decryptField(safeData.title) || safeData.title;
    safeData.message = decryptField(safeData.message) || safeData.message;
    return res.json({ success: true, data: safeData });
  } catch (err) {
    console.error('markAsRead error:', err);
    next(err);
  }
}

/**
 * Mark all notifications as read for current user
 */
export async function markAllAsRead(req, res, next) {
  try {
    const userId = req.user.id;
    const role = req.user.role;
    const isRoot = role === 'root' || req.user.dbRole === 'root';

    let query;
    if (isRoot) {
      query = {
        $and: [
          {
            $or: [
              { recipient: userId },
              { recipientRole: 'root' },
              { recipientRole: 'superadmin' },
              { recipientRole: 'all' }
            ]
          },
          { entityType: { $ne: 'lead' } },
          { title: { $not: /lead/i } }
        ],
        read: false
      };
    } else {
      const conditions = [
        { recipient: userId },
        ...(userObjId ? [{ recipient: userObjId }] : [])
      ];
      if (role) conditions.push({ recipientRole: role });
      if (dbRole && dbRole !== role) conditions.push({ recipientRole: dbRole });
      conditions.push({ recipientRole: 'all' });
      query = {
        $or: conditions,
        read: false
      };
    }

    await Notification.updateMany(
      query,
      { read: true, readAt: new Date() }
    );

    return res.json({ success: true, message: 'All notifications marked as read' });
  } catch (err) {
    console.error('markAllAsRead error:', err);
    next(err);
  }
}

/**
 * Delete a single notification
 */
export async function deleteNotification(req, res, next) {
  try {
    const { id } = req.params;
    await Notification.findByIdAndDelete(id);
    return res.json({ success: true, message: 'Notification deleted' });
  } catch (err) {
    console.error('deleteNotification error:', err);
    next(err);
  }
}

/**
 * Clear all notifications for the current user
 */
export async function clearAllNotifications(req, res, next) {
  try {
    const userId = req.user.id;
    const role = req.user.role;
    const dbRole = req.user.dbRole;
    const isRoot = role === 'root' || req.user.dbRole === 'root';

    let userObjId = null;
    try {
      userObjId = new mongoose.Types.ObjectId(userId);
    } catch (e) {}

    let query;
    if (isRoot) {
      query = {
        $and: [
          {
            $or: [
              { recipient: userId },
              { recipientRole: 'root' },
              { recipientRole: 'superadmin' },
              { recipientRole: 'all' }
            ]
          },
          { entityType: { $ne: 'lead' } },
          { title: { $not: /lead/i } }
        ]
      };
    } else {
      const conditions = [
        { recipient: userId },
        ...(userObjId ? [{ recipient: userObjId }] : [])
      ];
      if (role) conditions.push({ recipientRole: role });
      if (dbRole && dbRole !== role) conditions.push({ recipientRole: dbRole });
      conditions.push({ recipientRole: 'all' });
      query = { $or: conditions };
    }

    await Notification.deleteMany(query);
    return res.json({ success: true, message: 'All notifications cleared' });
  } catch (err) {
    console.error('clearAllNotifications error:', err);
    next(err);
  }
}
