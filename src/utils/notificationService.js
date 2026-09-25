import { sendMail, createTransporter } from './mailer.js';
import Settings from '../models/Settings.js';
import Admin from '../models/Admin.js';
import Notification from '../models/Notification.js';

/**
 * Notification Service
 * Handles sending system notifications (In-App, Email, etc.)
 */
class NotificationService {
  /**
   * Helper to create a persistent in-app notification
   */
  async createInAppNotification({
    recipient = null,
    recipientModel = 'None',
    recipientRole = null,
    title,
    message,
    type = 'info',
    entityType = 'lead',
    entityId = null,
    link = null,
    metadata = {}
  }) {
    try {
      if (!title || !message) return null;
      const notif = new Notification({
        recipient: recipient || null,
        recipientModel: recipientModel || 'None',
        recipientRole: recipientRole || null,
        title,
        message,
        type,
        entityType,
        entityId: entityId ? entityId.toString() : null,
        link: link || (entityType === 'lead' && entityId ? `/leads/${entityId}` : null),
        metadata,
        read: false,
        createdAt: new Date()
      });
      await notif.save();
      return notif;
    } catch (err) {
      console.error('Failed to create in-app notification:', err.message);
      return null;
    }
  }

  /**
   * Notify when a new lead arrives (e.g. from 3D Estimator, Bridge, or Manual creation)
   */
  async notifyLeadArrival(lead, { admin = null, superAdmin = null, rawCustomerName = null } = {}) {
    try {
      let customerName = rawCustomerName;
      if (!customerName) {
        const fn = lead.userInfo?.firstName || '';
        const ln = lead.userInfo?.lastName || '';
        if (fn && !fn.startsWith('gcm:')) {
          customerName = `${fn} ${ln}`.trim();
        } else if (lead.customerName && !lead.customerName.startsWith('gcm:')) {
          customerName = lead.customerName;
        } else if (lead.name && !lead.name.startsWith('gcm:')) {
          customerName = lead.name;
        }
      }

      const buildingType = lead.buildingType || 'Building';
      const displayName = customerName && !customerName.startsWith('gcm:')
        ? customerName
        : `${buildingType.charAt(0).toUpperCase() + buildingType.slice(1)} Lead`;

      const leadIdStr = lead._id ? lead._id.toString() : '';

      const title = 'New Lead Arrived';
      const message = `New lead received: ${displayName} (${buildingType})`;
      const link = `/leads/${leadIdStr}`;

      const adminId = admin?._id || admin || lead.managedByAdmin;
      let superAdminId = superAdmin?._id || superAdmin || lead.managedBySuperAdmin;

      if (adminId && !superAdminId) {
        try {
          const adm = await Admin.findById(adminId).select('createdById createdBy');
          if (adm) {
            superAdminId = adm.createdById || adm.createdBy;
          }
        } catch (e) {}
      }

      // 1. In-App notification for Managing Admin
      if (adminId) {
        await this.createInAppNotification({
          recipient: adminId,
          recipientModel: 'Admin',
          title,
          message,
          type: 'info',
          entityType: 'lead',
          entityId: leadIdStr,
          link
        });
      }

      // 2. In-App notification for Managing SuperAdmin / DSA
      if (superAdminId && String(superAdminId) !== String(adminId)) {
        await this.createInAppNotification({
          recipient: superAdminId,
          recipientModel: 'SuperAdmin',
          title,
          message,
          type: 'info',
          entityType: 'lead',
          entityId: leadIdStr,
          link
        });
      }

      // 3. In-App notification for Root Super Admin (platform-level awareness)
      await this.createInAppNotification({
        recipient: null,
        recipientRole: 'root',
        title,
        message,
        type: 'info',
        entityType: 'lead',
        entityId: leadIdStr,
        link
      });

      // 4. Also send email if configured for admin or SA
      if (admin && admin.email) {
        this.notifyNewLead(admin, lead).catch(err => console.error('Email error:', err));
      } else if (superAdmin && superAdmin.email) {
        this.notifyNewLead(superAdmin, lead).catch(err => console.error('Email error:', err));
      }
    } catch (err) {
      console.error('notifyLeadArrival error:', err);
    }
  }

  /**
   * Notify a user when a lead is assigned to them
   */
  async notifyLeadAssignment({ lead, userId, leadName = null }) {
    try {
      if (!userId || !lead) return;
      const fn = lead.userInfo?.firstName || '';
      const ln = lead.userInfo?.lastName || '';
      const candidate = leadName || (!fn.startsWith('gcm:') ? `${fn} ${ln}`.trim() : null) || lead.name || (lead.buildingType ? `${lead.buildingType} Lead` : 'Lead');
      const name = candidate.startsWith('gcm:') ? `${lead.buildingType || 'Building'} Lead` : candidate;
      const leadIdStr = lead._id ? lead._id.toString() : lead.toString();

      await this.createInAppNotification({
        recipient: userId,
        recipientModel: 'User',
        title: 'Lead Assigned to You',
        message: `You have been assigned to lead: ${name}`,
        type: 'success',
        entityType: 'lead',
        entityId: leadIdStr,
        link: `/leads/${leadIdStr}`
      });
    } catch (err) {
      console.error('notifyLeadAssignment error:', err);
    }
  }

  /**
   * Notify an admin when a lead is shared with them
   */
  async notifyLeadShared({ lead, adminId, leadName = null }) {
    try {
      if (!adminId || !lead) return;
      const fn = lead.userInfo?.firstName || '';
      const ln = lead.userInfo?.lastName || '';
      const candidate = leadName || (!fn.startsWith('gcm:') ? `${fn} ${ln}`.trim() : null) || lead.name || (lead.buildingType ? `${lead.buildingType} Lead` : 'Lead');
      const name = candidate.startsWith('gcm:') ? `${lead.buildingType || 'Building'} Lead` : candidate;
      const leadIdStr = lead._id ? lead._id.toString() : lead.toString();

      await this.createInAppNotification({
        recipient: adminId,
        recipientModel: 'Admin',
        title: 'Lead Shared with You',
        message: `Lead ${name} has been shared with you`,
        type: 'info',
        entityType: 'lead',
        entityId: leadIdStr,
        link: `/leads/${leadIdStr}`
      });
    } catch (err) {
      console.error('notifyLeadShared error:', err);
    }
  }

  /**
   * Notify creator when a new user is created
   */
  async notifyUserCreatedEvent({ user, creatorId }) {
    try {
      if (creatorId) {
        await this.createInAppNotification({
          recipient: creatorId,
          title: 'User Created',
          message: `Team member ${user.firstName || user.email} created successfully`,
          type: 'success',
          entityType: 'user',
          entityId: user._id ? user._id.toString() : null,
          link: '/users'
        });
      }
    } catch (err) {
      console.error('notifyUserCreatedEvent error:', err);
    }
  }

  /**
   * Helper to get a transporter for a specific user/admin
   */
  async getTransporterForUser(userId) {
    try {
      let settings = await Settings.findOne({ userId });

      if (settings?.integration?.smtpHost && settings?.integration?.smtpUser) {
        console.log(`Using custom SMTP integration for: ${settings.integration.smtpUser}`);
        return createTransporter({
          host: settings.integration.smtpHost,
          port: settings.integration.smtpPort || 587,
          user: settings.integration.smtpUser,
          pass: settings.integration.smtpPassword
        });
      }
    } catch (err) {
      console.warn('Could not load custom SMTP, falling back to default:', err.message);
    }
    return null;
  }

  /**
   * Specifically for new lead alerts via email
   */
  async notifyNewLead(user, lead) {
    const settings = await Settings.findOne({ userId: user.id || user._id });
    const isEnabled = settings ? settings.notifications.newLeadAlerts : true;
    if (!isEnabled) return;

    let adminId = user.adminId;
    const dynamicTransporter = await this.getTransporterForUser(adminId);

    const leadName = lead.userInfo?.firstName 
      ? `${lead.userInfo.firstName} ${lead.userInfo.lastName || ''}`.trim()
      : (lead.customerName || lead.name || 'N/A');

    const html = `
      <h3>New Lead Arrived</h3>
      <p>A new lead has arrived in your portal:</p>
      <ul>
        <li><strong>Lead Name:</strong> ${leadName}</li>
        <li><strong>Email:</strong> ${lead.userInfo?.email || lead.email || 'N/A'}</li>
        <li><strong>Building Type:</strong> ${lead.buildingType || 'N/A'}</li>
      </ul>
      <p>Login to your dashboard to view more details.</p>
    `;

    try {
      await sendMail({
        to: user.email,
        subject: 'New Lead Alert',
        text: `New lead arrived: ${leadName}`,
        html,
        transporter: dynamicTransporter || undefined
      });
      console.log(`Notification sent to ${user.email} (Custom SMTP: ${!!dynamicTransporter})`);
    } catch (error) {
      console.error(`Failed to send lead notification with ${dynamicTransporter ? 'custom' : 'default'} SMTP:`, error.message);
      
      if (dynamicTransporter) {
        console.warn('Attempting fallback to system default SMTP...');
        try {
          await sendMail({
            to: user.email,
            subject: 'New Lead Alert (System Fallback)',
            text: `New lead arrived: ${leadName}`,
            html
          });
          console.log('Fallback notification sent successfully.');
        } catch (fallbackErr) {
          console.error('Critical: System fallback SMTP also failed:', fallbackErr.message);
        }
      }
    }
  }

  /**
   * Notify when a new user is created via email
   */
  async notifyUserCreated(newUser, rawPassword) {
    const dynamicTransporter = await this.getTransporterForUser(newUser.adminId);

    const html = `
      <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
        <h2 style="color: #333;">Welcome to the Platform!</h2>
        <p>Hello ${newUser.firstName},</p>
        <p>An account has been created for you. Here are your login credentials:</p>
        <div style="background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 5px 0;"><strong>Email:</strong> ${newUser.email}</p>
          <p style="margin: 5px 0;"><strong>Password:</strong> ${rawPassword}</p>
        </div>
        <p>Please login and change your password immediately.</p>
        <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;" />
        <p style="font-size: 12px; color: #777;">This is an automated message. Please do not reply.</p>
      </div>
    `;

    try {
      await sendMail({
        to: newUser.email,
        subject: 'Your New Account Details',
        text: `Welcome! Your login is ${newUser.email} and password is ${rawPassword}`,
        html,
        transporter: dynamicTransporter || undefined
      });
      console.log(`Welcome email sent to ${newUser.email}`);
    } catch (error) {
      console.error(`Failed to send welcome email with ${dynamicTransporter ? 'custom' : 'default'} SMTP:`, error.message);
      
      if (dynamicTransporter) {
         console.warn('Attempting fallback to system default SMTP...');
         try {
           await sendMail({
             to: newUser.email,
             subject: 'Your New Account Details (System Fallback)',
             text: `Welcome! Your login is ${newUser.email} and password is ${rawPassword}`,
             html
           });
           console.log('Fallback welcome email sent successfully.');
         } catch (fallbackErr) {
           console.error('Critical: System fallback SMTP also failed:', fallbackErr.message);
         }
      }
    }
  }
}

export default new NotificationService();
