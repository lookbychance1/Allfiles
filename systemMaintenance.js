/**
 * systemMaintenance.js — System Maintenance & Health Management
 * Features: maintenance mode toggle, health checks, cache flush,
 *           DB stats, process info, scheduled downtime, disk/memory stats
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const os       = require('os');
const fs       = require('fs');
const path     = require('path');

const router = express.Router();
const { requireRole } = require('./adminMiddleware');

// ─── Maintenance Config Schema ────────────────────────────────────────────────
const MaintenanceSchema = new mongoose.Schema({
  isActive:        { type: Boolean, default: false },
  message:         { type: String, default: 'System is under maintenance. Please try again later.' },
  estimatedEndISO: { type: String, default: '' },
  allowedIPs:      { type: [String], default: [] }, // IPs that bypass maintenance
  activatedBy:     { type: String, default: '' },
  activatedAt:     { type: Date, default: null },
  updatedAt:       { type: Date, default: Date.now },
}, { collection: 'maintenance_config', capped: { size: 10240, max: 1 } });

const MaintenanceConfig = mongoose.models.MaintenanceConfig || mongoose.model('MaintenanceConfig', MaintenanceSchema);

// ─── GET /api/admin/maintenance/status ───────────────────────────────────────
router.get('/status', async (req, res) => {
  try {
    let config = await MaintenanceConfig.findOne().lean();
    if (!config) config = { isActive: false, message: '', estimatedEndISO: '', allowedIPs: [] };
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch maintenance status.' });
  }
});

// ─── POST /api/admin/maintenance/toggle ──────────────────────────────────────
router.post('/toggle', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const { isActive, message, estimatedEndISO, allowedIPs } = req.body;

    const update = {
      isActive:        Boolean(isActive),
      message:         message || 'System is under maintenance.',
      estimatedEndISO: estimatedEndISO || '',
      allowedIPs:      allowedIPs || [],
      activatedBy:     req.admin.username,
      activatedAt:     isActive ? new Date() : null,
      updatedAt:       new Date(),
    };

    const config = await MaintenanceConfig.findOneAndUpdate({}, update, { upsert: true, new: true });

    // Notify via Redis pub/sub so all cluster workers pick it up instantly
    const redis = req.app.get('redis');
    if (redis) {
      await redis.set('maintenance:active', isActive ? '1' : '0');
      await redis.set('maintenance:message', message || '');
    }

    res.json({ message: `Maintenance mode ${isActive ? 'ENABLED' : 'DISABLED'}.`, config });
  } catch (err) {
    res.status(500).json({ error: 'Toggle failed.', detail: err.message });
  }
});

// ─── GET /api/admin/maintenance/health ───────────────────────────────────────
router.get('/health', async (req, res) => {
  try {
    const redis   = req.app.get('redis');
    const redisPing = redis ? await redis.ping().catch(() => 'ERROR') : 'NOT_CONFIGURED';
    const mongoPing = mongoose.connection.readyState === 1 ? 'OK' : 'ERROR';

    // Disk usage of current drive
    const uploadDir = process.env.QUESTION_IMG_DIR || path.join(__dirname, 'uploads');
    let diskUsage = null;
    try {
      const stats = fs.statSync(uploadDir);
      diskUsage = { path: uploadDir, exists: true };
    } catch { diskUsage = { path: uploadDir, exists: false }; }

    res.json({
      status:   mongoPing === 'OK' && redisPing === 'PONG' ? 'healthy' : 'degraded',
      uptime:   process.uptime(),
      memoryMB: {
        rss:       (process.memoryUsage().rss       / 1048576).toFixed(1),
        heapUsed:  (process.memoryUsage().heapUsed  / 1048576).toFixed(1),
        heapTotal: (process.memoryUsage().heapTotal / 1048576).toFixed(1),
      },
      system: {
        platform:    os.platform(),
        cpuCount:    os.cpus().length,
        totalMemGB:  (os.totalmem()  / 1073741824).toFixed(2),
        freeMemGB:   (os.freemem()   / 1073741824).toFixed(2),
        loadAvg:     os.loadavg(),
        hostname:    os.hostname(),
        nodeVersion: process.version,
      },
      services: {
        mongodb: mongoPing,
        redis:   redisPing === 'PONG' ? 'OK' : redisPing,
      },
      diskUsage,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Health check failed.', detail: err.message });
  }
});

// ─── POST /api/admin/maintenance/flush-cache ─────────────────────────────────
router.post('/flush-cache', requireRole('superadmin'), async (req, res) => {
  try {
    const redis  = req.app.get('redis');
    const { pattern } = req.body; // e.g. 'session:*'

    if (!redis) return res.status(503).json({ error: 'Redis not available.' });

    let deletedCount = 0;
    if (pattern) {
      const keys = await redis.keys(pattern);
      if (keys.length) {
        await redis.del(keys);
        deletedCount = keys.length;
      }
    } else {
      await redis.flushDb();
      deletedCount = -1; // all
    }

    res.json({ message: 'Cache flushed.', deletedKeys: deletedCount === -1 ? 'all' : deletedCount });
  } catch (err) {
    res.status(500).json({ error: 'Cache flush failed.', detail: err.message });
  }
});

// ─── GET /api/admin/maintenance/db-stats ─────────────────────────────────────
router.get('/db-stats', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const db     = mongoose.connection.db;
    const stats  = await db.stats();
    const cols   = await db.listCollections().toArray();
    const colStats = await Promise.all(
      cols.map(async c => {
        const s = await db.collection(c.name).stats().catch(() => null);
        return s ? { collection: c.name, count: s.count, sizeMB: (s.size / 1048576).toFixed(2) } : null;
      })
    );

    res.json({
      dbSizeMB:      (stats.dataSize  / 1048576).toFixed(2),
      storageSizeMB: (stats.storageSize / 1048576).toFixed(2),
      indexSizeMB:   (stats.indexSize  / 1048576).toFixed(2),
      collections:   colStats.filter(Boolean).sort((a,b) => b.count - a.count),
    });
  } catch (err) {
    res.status(500).json({ error: 'DB stats failed.', detail: err.message });
  }
});

// ─── POST /api/admin/maintenance/cleanup ─────────────────────────────────────
// Manual trigger for nightly cleanup tasks
router.post('/cleanup', requireRole('superadmin'), async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const cutoff = new Date(Date.now() - 30 * 86400000); // 30 days ago

    const [sessions, liveSessions, staleAudit] = await Promise.all([
      db.collection('exam_sessions').deleteMany({ updatedAt: { $lt: cutoff }, status: 'finished' }),
      db.collection('live_exam_sessions').deleteMany({ createdAt: { $lt: cutoff } }),
      db.collection('admin_audit_logs').deleteMany({ timestamp: { $lt: new Date(Date.now() - 90 * 86400000) } }),
    ]);

    res.json({
      message: 'Cleanup complete.',
      deletedExamSessions:     sessions.deletedCount,
      deletedLiveSessions:     liveSessions.deletedCount,
      deletedAuditLogs:        staleAudit.deletedCount,
    });
  } catch (err) {
    res.status(500).json({ error: 'Cleanup failed.', detail: err.message });
  }
});

// ─── GET /api/admin/maintenance/logs ─────────────────────────────────────────
router.get('/logs', requireRole('superadmin', 'admin'), async (req, res) => {
  try {
    const logFile = process.env.ADMIN_LOG_FILE || path.join(__dirname, 'logs', 'admin-access.log');
    const lines   = parseInt(req.query.lines) || 100;

    if (!fs.existsSync(logFile)) return res.json({ logs: [] });

    const content = fs.readFileSync(logFile, 'utf8');
    const allLines = content.trim().split('\n');
    const lastN   = allLines.slice(-lines).reverse();

    res.json({ logs: lastN, total: allLines.length });
  } catch (err) {
    res.status(500).json({ error: 'Log read failed.' });
  }
});

module.exports = router;
module.exports.MaintenanceConfig = MaintenanceConfig;
