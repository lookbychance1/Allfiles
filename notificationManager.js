/**
 * notificationManager.js — Push & In-App Notification System
 * Supports: in-app banners, email blasts, web push (via web-push lib)
 * Targets: all users, segment, or individual user
 */

require('dotenv').config();
const express   = require('express');
const mongoose  = require('mongoose');
const webpush   = require('web-push');
const nodemailer = require('nodemailer');

const router = express.Router();
const { requireRole } = require('./adminMiddleware');

// ─── Web Push Setup ───────────────────────────────────────────────────────────
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    `mailto:${process.env.ADMIN_EMAIL || 'admin@solvemcq.com'}`,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY,
  );
}

// ─── Email Transporter ────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_PORT === '465',
  auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ─── Schemas ──────────────────────────────────────────────────────────────────
const PushSubSchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  subscription: mongoose.Schema.Types.Mixed, // { endpoint, keys: { p256dh, auth } }
  createdAt:    { type: Date, default: Date.now },
}, { collection: 'push_subscriptions' });

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

const PushSub      = mongoose.models.PushSub      || mongoose.model('PushSub', PushSubSchema);
const Notification = mongoose.models.Notification || mongoose.model('Notification', NotificationSchema);

// ─── GET /api/admin/notifications ────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const [notifs, total] = await Promise.all([
      Notification.find().sort({ createdAt: -1 }).skip((page-1)*limit).limit(limit).lean(),
      Notification.countDocuments(),
    ]);
    res.json({ notifications: notifs, total, page, pages: Math.ceil(total/limit) });
  } catch { res.status(500).json({ error: 'Fetch failed.' }); }
});

// ─── POST /api/admin/notifications ───────────────────────────────────────────
router.post('/', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { title, body, type, target, targetUserId, imageUrl, actionUrl } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'title and body required.' });

    const notif = await Notification.create({
      title, body, type: type || 'banner',
      target: target || 'all',
      targetUserId: targetUserId || null,
      imageUrl: imageUrl || '', actionUrl: actionUrl || '',
      createdBy: req.admin.username,
    });
    res.status(201).json(notif);
  } catch (err) {
    res.status(500).json({ error: 'Creation failed.', detail: err.message });
  }
});

// ─── POST /api/admin/notifications/:id/send ──────────────────────────────────
router.post('/:id/send', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const notif = await Notification.findById(req.params.id);
    if (!notif) return res.status(404).json({ error: 'Notification not found.' });

    let sentCount = 0, failCount = 0;

    if (notif.type === 'push' || notif.type === 'all') {
      // Fetch target subscriptions
      const filter = {};
      if (notif.target === 'user' && notif.targetUserId) filter.userId = notif.targetUserId;

      const subs = await PushSub.find(filter).lean();
      const payload = JSON.stringify({
        title:    notif.title,
        body:     notif.body,
        icon:     notif.imageUrl || '/icon.png',
        data:     { url: notif.actionUrl || '/' },
      });

      await Promise.allSettled(subs.map(async sub => {
        try {
          await webpush.sendNotification(sub.subscription, payload);
          sentCount++;
        } catch (e) {
          failCount++;
          if (e.statusCode === 410) await PushSub.deleteOne({ _id: sub._id }); // expired sub
        }
      }));
    }

    if (notif.type === 'email' || notif.type === 'all') {
      const UserModel = mongoose.model('User');
      const filter    = {};
      if (notif.target !== 'all') filter.plan = notif.target;
      if (notif.target === 'user' && notif.targetUserId) filter._id = notif.targetUserId;

      const users = await UserModel.find(filter).select('email').lean();
      for (const user of users) {
        try {
          await transporter.sendMail({
            from:    `"SolveMCQ" <${process.env.SMTP_USER}>`,
            to:      user.email,
            subject: notif.title,
            html:    `<h2>${notif.title}</h2><p>${notif.body}</p>${notif.actionUrl ? `<a href="${notif.actionUrl}">View more</a>` : ''}`,
          });
          sentCount++;
        } catch { failCount++; }
      }
    }

    notif.sentCount = sentCount;
    notif.failCount = failCount;
    notif.sentAt    = new Date();
    await notif.save();

    res.json({ message: 'Notification sent.', sentCount, failCount });
  } catch (err) {
    res.status(500).json({ error: 'Send failed.', detail: err.message });
  }
});

// ─── DELETE /api/admin/notifications/:id ─────────────────────────────────────
router.delete('/:id', requireRole('superadmin'), async (req, res) => {
  try {
    await Notification.findByIdAndDelete(req.params.id);
    res.json({ message: 'Notification deleted.' });
  } catch { res.status(500).json({ error: 'Delete failed.' }); }
});

// ─── POST /api/admin/notifications/subscribe ─────────────────────────────────
// Called by users/admins to register push subscription
router.post('/subscribe', async (req, res) => {
  try {
    const { userId, subscription } = req.body;
    if (!subscription?.endpoint) return res.status(400).json({ error: 'Invalid subscription.' });
    await PushSub.findOneAndUpdate(
      { 'subscription.endpoint': subscription.endpoint },
      { userId: userId || null, subscription },
      { upsert: true, new: true },
    );
    res.json({ message: 'Subscribed.' });
  } catch { res.status(500).json({ error: 'Subscribe failed.' }); }
});

// ─── GET /api/admin/notifications/active-banners ─────────────────────────────
// Served to admin frontend for in-app banners
router.get('/active-banners', async (req, res) => {
  try {
    const banners = await Notification.find({
      type: { $in: ['banner', 'all'] },
      isActive: true,
    }).sort({ createdAt: -1 }).limit(5).lean();
    res.json(banners);
  } catch { res.status(500).json({ error: 'Failed.' }); }
});

module.exports = router;
