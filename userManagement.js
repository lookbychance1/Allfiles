/**
 * userManagement.js — Complete User Management Routes
 * CRUD + search + ban + unlock + auth history + login logs
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const router = express.Router();
const { requireRole } = require('./adminMiddleware');

// ─── Reuse main app's User model (same MongoDB) ───────────────────────────────
const UserSchema = new mongoose.Schema({
  email:          { type: String, index: true },
  phone:          { type: String, sparse: true },
  applicationNo:  { type: String, sparse: true },
  passwordHash:   String,
  authMethod:     { type: String, enum: ['email_otp', 'google', 'github', 'apple', 'legacy', 'phone_otp'], default: 'email_otp' },
  isVerified:     { type: Boolean, default: false },
  isBanned:       { type: Boolean, default: false },
  banReason:      { type: String, default: '' },
  bannedAt:       Date,
  bannedBy:       String,
  plan:           { type: String, enum: ['free', 'pro', 'premium'], default: 'free' },
  planExpiry:     Date,
  examPreference: String,
  totalSessions:  { type: Number, default: 0 },
  lastActiveAt:   Date,
  loginHistory:   [{
    ip:        String,
    userAgent: String,
    method:    String,
    timestamp: { type: Date, default: Date.now },
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, { collection: 'users' });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ─── GET /api/admin/users — list with pagination + search + filters ───────────
router.get('/', async (req, res) => {
  try {
    const page    = Math.max(1, parseInt(req.query.page)  || 1);
    const limit   = Math.min(100, parseInt(req.query.limit) || 20);
    const skip    = (page - 1) * limit;
    const search  = req.query.search?.trim();
    const filter  = {};

    if (search) {
      filter.$or = [
        { email:         { $regex: search, $options: 'i' } },
        { phone:         { $regex: search, $options: 'i' } },
        { applicationNo: { $regex: search, $options: 'i' } },
      ];
    }
    if (req.query.plan)       filter.plan       = req.query.plan;
    if (req.query.authMethod) filter.authMethod = req.query.authMethod;
    if (req.query.isBanned !== undefined) filter.isBanned = req.query.isBanned === 'true';
    if (req.query.isVerified !== undefined) filter.isVerified = req.query.isVerified === 'true';

    const [users, total] = await Promise.all([
      User.find(filter)
        .select('-passwordHash -loginHistory')
        .sort({ createdAt: -1 })
        .skip(skip).limit(limit)
        .lean(),
      User.countDocuments(filter),
    ]);

    res.json({ users, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// ─── GET /api/admin/users/stats ───────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const [
      total, verified, banned,
      byAuth, byPlan,
      newToday, newThisWeek,
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ isVerified: true }),
      User.countDocuments({ isBanned: true }),
      User.aggregate([{ $group: { _id: '$authMethod', count: { $sum: 1 } } }]),
      User.aggregate([{ $group: { _id: '$plan', count: { $sum: 1 } } }]),
      User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
      User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 7 * 86400000) } }),
    ]);

    res.json({
      total, verified, banned,
      authMethods: Object.fromEntries(byAuth.map(a => [a._id || 'unknown', a.count])),
      plans:       Object.fromEntries(byPlan.map(p => [p._id || 'free', p.count])),
      newToday, newThisWeek,
    });
  } catch (err) {
    res.status(500).json({ error: 'Stats failed.' });
  }
});

// ─── GET /api/admin/users/:id ─────────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
  } catch {
    res.status(400).json({ error: 'Invalid user ID.' });
  }
});

// ─── PATCH /api/admin/users/:id ───────────────────────────────────────────────
router.patch('/:id', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const allowed = ['email', 'phone', 'applicationNo', 'plan', 'planExpiry', 'examPreference', 'isVerified'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) updates[key] = req.body[key];
    }
    updates.updatedAt = new Date();

    const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Update failed.' });
  }
});

// ─── POST /api/admin/users/:id/ban ────────────────────────────────────────────
router.post('/:id/ban', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, {
      isBanned: true, banReason: reason || 'Banned by admin.',
      bannedAt: new Date(), bannedBy: req.admin.username,
    }, { new: true }).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Revoke active sessions in Redis
    const redis = req.app.get('redis');
    if (redis) await redis.del(`user_sessions:${req.params.id}`);

    res.json({ message: 'User banned.', user });
  } catch (err) {
    res.status(500).json({ error: 'Ban failed.' });
  }
});

// ─── POST /api/admin/users/:id/unban ─────────────────────────────────────────
router.post('/:id/unban', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, {
      isBanned: false, banReason: '', bannedAt: null, bannedBy: null,
    }, { new: true }).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ message: 'User unbanned.', user });
  } catch (err) {
    res.status(500).json({ error: 'Unban failed.' });
  }
});

// ─── DELETE /api/admin/users/:id ─────────────────────────────────────────────
router.delete('/:id', requireRole('superadmin'), async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: 'User deleted.' });
  } catch {
    res.status(500).json({ error: 'Deletion failed.' });
  }
});

// ─── GET /api/admin/users/:id/login-history ──────────────────────────────────
router.get('/:id/login-history', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('loginHistory email').lean();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const history = (user.loginHistory || []).sort((a,b) => b.timestamp - a.timestamp).slice(0, 50);
    res.json({ email: user.email, history });
  } catch {
    res.status(400).json({ error: 'Invalid user ID.' });
  }
});

// ─── POST /api/admin/users/:id/reset-password ────────────────────────────────
router.post('/:id/reset-password', requireRole('superadmin'), async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'Password too short.' });
    const hash = await bcrypt.hash(newPassword, 12);
    await User.findByIdAndUpdate(req.params.id, { passwordHash: hash, updatedAt: new Date() });
    res.json({ message: 'Password reset.' });
  } catch {
    res.status(500).json({ error: 'Reset failed.' });
  }
});

// ─── GET /api/admin/users/export/csv ─────────────────────────────────────────
router.get('/export/csv', requireRole('superadmin'), async (req, res) => {
  try {
    const users = await User.find().select('email phone applicationNo authMethod plan isVerified isBanned createdAt').lean();
    const headers = 'email,phone,applicationNo,authMethod,plan,isVerified,isBanned,createdAt\n';
    const rows = users.map(u =>
      `"${u.email||''}","${u.phone||''}","${u.applicationNo||''}","${u.authMethod||''}","${u.plan||''}","${u.isVerified}","${u.isBanned}","${u.createdAt?.toISOString()||''}"`
    ).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
    res.send(headers + rows);
  } catch {
    res.status(500).json({ error: 'Export failed.' });
  }
});

module.exports = router;
