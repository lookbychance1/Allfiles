const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  body:        { type: String, required: true },
  type:        { type: String, enum: ['banner', 'push', 'email', 'all'], default: 'banner' },
  target:      { type: String, enum: ['all', 'free', 'pro', 'premium', 'user'], default: 'all' },
  targetUserId:{ type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  imageUrl:    { type: String, default: '' },
  actionUrl:   { type: String, default: '' },
  isActive:    { type: Boolean, default: true },
  sentCount:   { type: Number, default: 0 },
  failCount:   { type: Number, default: 0 },
  sentAt:      { type: Date, default: null },
  createdBy:   { type: String, default: 'admin' },
  createdAt:   { type: Date, default: Date.now },
}, { collection: 'notifications' });

module.exports = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);
