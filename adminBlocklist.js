/**
 * adminBlocklist.js — Extended Blocklist Management
 * Extends corsBlocklist.js with admin CRUD interface
 * Manages: IP blocks, domain blocks, permanent bans, manual blocks
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const { requireRole } = require('./adminMiddleware');

const router = express.Router();

// ─── Blocklist Schema ─────────────────────────────────────────────────────────
const BlockSchema = new mongoose.Schema({
  type:        { type: String, enum: ['ip', 'domain', 'user', 'asn'], required: true, index: true },
  value:       { type: String, required: true, index: true },
  reason:      { type: String, default: '' },
  severity:    { type: String, enum: ['temp', 'permanent', 'shadow'], default: 'temp' },
  expiresAt:   { type: Date, default: null },        // null = permanent
  addedBy:     { type: String, default: 'system' },
  addedAt:     { type: Date, default: Date.now },
  hitCount:    { type: Number, default: 0 },         // how many times blocked
  lastHitAt:   { type: Date, default: null },
  autoBlocked: { type: Boolean, default: false },    // added by corsBlocklist.js auto-detection
}, { collection: 'admin_blocklist' });

BlockSchema.index({ type: 1, value: 1 }, { unique: true });

const Block = mongoose.models.Block || mongoose.model('Block', BlockSchema);

// ─── GET /api/admin/blocklist ─────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page) || 1);
    const limit    = Math.min(100, parseInt(req.query.limit) || 20);
    const filter   = {};

    if (req.query.type)       filter.type     = req.query.type;
    if (req.query.severity)   filter.severity = req.query.severity;
    if (req.query.autoBlocked !== undefined) filter.autoBlocked = req.query.autoBlocked === 'true';
    if (req.query.search) {
      filter.value = { $regex: req.query.search, $options: 'i' };
    }
    // Show only active (not expired)
    if (req.query.activeOnly !== 'false') {
      filter.$or = [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }];
    }

    const [blocks, total] = await Promise.all([
      Block.find(filter).sort({ addedAt: -1 }).skip((page-1)*limit).limit(limit).lean(),
      Block.countDocuments(filter),
    ]);

    res.json({ blocks, total, page, pages: Math.ceil(total/limit) });
  } catch (err) {
    res.status(500).json({ error: 'Fetch failed.' });
  }
});

// ─── GET /api/admin/blocklist/stats ──────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const [total, byType, bySeverity, autoBlocked, expiredToday] = await Promise.all([
      Block.countDocuments(),
      Block.aggregate([{ $group: { _id: '$type', count: { $sum: 1 } } }]),
      Block.aggregate([{ $group: { _id: '$severity', count: { $sum: 1 } } }]),
      Block.countDocuments({ autoBlocked: true }),
      Block.countDocuments({ expiresAt: { $lt: new Date(), $gte: new Date(Date.now() - 86400000) } }),
    ]);
    res.json({
      total,
      byType:     Object.fromEntries(byType.map(t => [t._id, t.count])),
      bySeverity: Object.fromEntries(bySeverity.map(s => [s._id, s.count])),
      autoBlocked,
      expiredToday,
    });
  } catch { res.status(500).json({ error: 'Stats failed.' }); }
});

// ─── POST /api/admin/blocklist ────────────────────────────────────────────────
router.post('/', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { type, value, reason, severity, durationHours } = req.body;
    if (!type || !value) return res.status(400).json({ error: 'type and value required.' });

    const expiresAt = severity === 'permanent' || !durationHours
      ? null
      : new Date(Date.now() + durationHours * 3600000);

    const block = await Block.findOneAndUpdate(
      { type, value },
      {
        type, value,
        reason:    reason || '',
        severity:  severity || 'temp',
        expiresAt,
        addedBy:   req.admin.username,
        addedAt:   new Date(),
      },
      { upsert: true, new: true },
    );

    // Sync to Redis for real-time enforcement
    const redis = req.app.get('redis');
    if (redis && type === 'ip') {
      const key = `blocked:ip:${value}`;
      if (expiresAt) {
        const ttl = Math.ceil((expiresAt - Date.now()) / 1000);
        await redis.setEx(key, ttl, reason || 'admin block');
      } else {
        await redis.set(key, reason || 'admin block');
      }
    }

    res.status(201).json(block);
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'Entry already exists. Use PATCH to update.' });
    res.status(500).json({ error: 'Add failed.', detail: err.message });
  }
});

// ─── PATCH /api/admin/blocklist/:id ──────────────────────────────────────────
router.patch('/:id', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const allowed = ['reason', 'severity', 'expiresAt'];
    const updates = {};
    for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];

    const block = await Block.findByIdAndUpdate(req.params.id, updates, { new: true });
    if (!block) return res.status(404).json({ error: 'Block not found.' });
    res.json(block);
  } catch { res.status(500).json({ error: 'Update failed.' }); }
});

// ─── DELETE /api/admin/blocklist/:id ─────────────────────────────────────────
router.delete('/:id', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const block = await Block.findByIdAndDelete(req.params.id);
    if (!block) return res.status(404).json({ error: 'Block not found.' });

    // Remove from Redis
    const redis = req.app.get('redis');
    if (redis && block.type === 'ip') {
      await redis.del(`blocked:ip:${block.value}`);
    }

    res.json({ message: 'Block removed.' });
  } catch { res.status(500).json({ error: 'Delete failed.' }); }
});

// ─── POST /api/admin/blocklist/bulk-remove ────────────────────────────────────
router.post('/bulk-remove', requireRole('superadmin'), async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required.' });

    const blocks = await Block.find({ _id: { $in: ids } }).lean();
    await Block.deleteMany({ _id: { $in: ids } });

    // Clean Redis
    const redis = req.app.get('redis');
    if (redis) {
      const ipBlocks = blocks.filter(b => b.type === 'ip');
      if (ipBlocks.length) await redis.del(ipBlocks.map(b => `blocked:ip:${b.value}`));
    }

    res.json({ message: `${blocks.length} blocks removed.` });
  } catch { res.status(500).json({ error: 'Bulk remove failed.' }); }
});

// ─── POST /api/admin/blocklist/cleanup-expired ────────────────────────────────
router.post('/cleanup-expired', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const result = await Block.deleteMany({ expiresAt: { $lt: new Date() } });
    res.json({ message: `${result.deletedCount} expired blocks removed.` });
  } catch { res.status(500).json({ error: 'Cleanup failed.' }); }
});

// ─── GET /api/admin/blocklist/check?type=ip&value=1.2.3.4 ────────────────────
router.get('/check', async (req, res) => {
  try {
    const { type, value } = req.query;
    if (!type || !value) return res.status(400).json({ error: 'type and value required.' });

    const block = await Block.findOne({
      type, value,
      $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
    }).lean();

    res.json({ blocked: Boolean(block), block: block || null });
  } catch { res.status(500).json({ error: 'Check failed.' }); }
});

module.exports = router;
