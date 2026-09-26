import mongoose from 'mongoose';
import { encryptField, decryptField } from '../utils/encryption.js';

const NotificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'recipientModel',
    default: null
  },
  recipientModel: {
    type: String,
    default: null
  },
  recipientRole: {
    type: String,
    default: null
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['info', 'success', 'warning', 'error'],
    default: 'info'
  },
  entityType: {
    type: String,
    enum: ['lead', 'user', 'admin', 'settings', 'system'],
    default: 'lead'
  },
  entityId: {
    type: String,
    default: null
  },
  link: {
    type: String,
    default: null
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  read: {
    type: Boolean,
    default: false
  },
  readAt: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Automatically encrypt notification details (title & message) at rest in the database
NotificationSchema.pre('save', function (next) {
  if (this.title && !this.title.startsWith('gcm:')) {
    const enc = encryptField(this.title);
    if (enc) this.title = enc;
  }
  if (this.message && !this.message.startsWith('gcm:')) {
    const enc = encryptField(this.message);
    if (enc) this.message = enc;
  }
  next();
});

// Decrypt fields after retrieval when loaded as a Mongoose document
NotificationSchema.post('init', function (doc) {
  if (doc.title && doc.title.startsWith('gcm:')) {
    doc.title = decryptField(doc.title) || doc.title;
  }
  if (doc.message && doc.message.startsWith('gcm:')) {
    doc.message = decryptField(doc.message) || doc.message;
  }
});

NotificationSchema.methods.getDecryptedTitle = function () {
  return decryptField(this.title) || this.title;
};

NotificationSchema.methods.getDecryptedMessage = function () {
  return decryptField(this.message) || this.message;
};

NotificationSchema.index({ recipient: 1, read: 1, createdAt: -1 });
NotificationSchema.index({ recipientRole: 1, read: 1, createdAt: -1 });
NotificationSchema.index({ createdAt: -1 });

export default mongoose.model('Notification', NotificationSchema);
