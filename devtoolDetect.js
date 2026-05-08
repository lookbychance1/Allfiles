/**
 * devtoolDetect.js — Backend DevTool Detection & Access Revocation
 *
 * How it works:
 *  1. Frontend JS uses multiple detection methods (resize, debugger timing, perf, keys)
 *  2. On detection, frontend POSTs a beacon to /api/admin/devtool/report
 *  3. Backend logs incident in MongoDB, increments Redis counter
 *  4. After threshold (3 incidents), admin session is revoked
 *  5. All API calls then return 403 DEVTOOL_BLOCKED (enforced by devtoolBlock middleware)
 *
 * Frontend snippet to embed in admin SPA is exported at bottom of this file.
 */

require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');

const router = express.Router();

// ─── Incident Schema ──────────────────────────────────────────────────────────
const IncidentSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', default: null },
  username:  { type: String, default: 'unknown' },
  ip:        { type: String, default: '' },
  userAgent: { type: String, default: '' },
  method:    { type: String, enum: ['resize', 'debugger', 'perf', 'keys', 'beacon', 'unknown'], default: 'unknown' },
  sessionId: { type: String, default: '' },
  blocked:   { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_devtool_incidents' });

const Incident = mongoose.models.DevToolIncident || mongoose.model('DevToolIncident', IncidentSchema);

// ─── Helper ───────────────────────────────────────────────────────────────────
function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
}

const BLOCK_THRESHOLD = parseInt(process.env.DEVTOOL_BLOCK_THRESHOLD) || 3;
const BLOCK_TTL_SEC   = parseInt(process.env.DEVTOOL_BLOCK_TTL)       || 3600; // 1 hour

// ─── POST /api/admin/devtool/report ──────────────────────────────────────────
// Called by frontend when devtools is detected.
// Works even if the user is not authenticated yet (to catch login-page snoopers).
router.post('/report', async (req, res) => {
  const { adminId, username, method, sessionId } = req.body;
  const ip        = getIp(req);
  const userAgent = req.headers['user-agent'] || '';

  try {
    const redis = req.app.get('redis');
    let blocked = false;

    if (adminId && redis) {
      const key   = `devtool:block:${adminId}`;
      const count = await redis.incr(key);
      await redis.expire(key, BLOCK_TTL_SEC);

      if (count >= BLOCK_THRESHOLD) {
        blocked = true;
        // Also revoke all refresh tokens by marking in Redis
        await redis.setEx(`devtool:revoked:${adminId}`, BLOCK_TTL_SEC, '1');
      }
    }

    await Incident.create({
      adminId:   adminId || null,
      username:  username || 'unknown',
      ip,
      userAgent,
      method:    method || 'unknown',
      sessionId: sessionId || '',
      blocked,
    });

    res.json({ received: true, blocked });
  } catch (err) {
    console.error('[devtoolDetect] Error:', err);
    res.status(500).json({ error: 'Report failed.' });
  }
});

// ─── GET /api/admin/devtool/incidents ─────────────────────────────────────────
// Protected — called from within the dashboard to view incidents
router.get('/incidents', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 20);
    const skip  = (page - 1) * limit;

    const [incidents, total] = await Promise.all([
      Incident.find().sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      Incident.countDocuments(),
    ]);

    res.json({ incidents, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch incidents.' });
  }
});

// ─── DELETE /api/admin/devtool/unblock/:adminId ───────────────────────────────
router.delete('/unblock/:adminId', async (req, res) => {
  try {
    const redis = req.app.get('redis');
    const { adminId } = req.params;
    if (redis) {
      await redis.del(`devtool:block:${adminId}`);
      await redis.del(`devtool:revoked:${adminId}`);
    }
    res.json({ message: 'Admin unblocked from DevTool ban.' });
  } catch (err) {
    res.status(500).json({ error: 'Unblock failed.' });
  }
});

// ─── Frontend Detection Snippet ───────────────────────────────────────────────
// Embed this in your admin SPA's <script> tag
const FRONTEND_DEVTOOL_SNIPPET = `
(function() {
  'use strict';

  const REPORT_URL = '/api/admin/devtool/report';
  let reported = false;

  function getAdminMeta() {
    try {
      const token = localStorage.getItem('admin_access_token') || '';
      if (!token) return {};
      const payload = JSON.parse(atob(token.split('.')[1]));
      return { adminId: payload.id, username: payload.username };
    } catch { return {}; }
  }

  async function report(method) {
    if (reported) return;
    reported = true;
    const meta = getAdminMeta();
    try {
      await fetch(REPORT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...meta, method, sessionId: window.__adminSessionId || '' }),
        keepalive: true,
      });
    } catch(e) {}
    // Optionally clear the UI immediately
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;background:#0f172a;color:#f87171;font-size:18px">Access revoked. DevTools usage detected.</div>';
  }

  // Method 1: Window resize heuristic
  const threshold = 160;
  function checkResize() {
    const widthDiff  = window.outerWidth  - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    if (widthDiff > threshold || heightDiff > threshold) report('resize');
  }
  setInterval(checkResize, 1000);
  window.addEventListener('resize', checkResize);

  // Method 2: Debugger timing
  function checkDebugger() {
    const start = performance.now();
    debugger;
    const elapsed = performance.now() - start;
    if (elapsed > 100) report('debugger');
  }
  setInterval(checkDebugger, 3000);

  // Method 3: Performance timing deviation
  function checkPerf() {
    const t0 = performance.now();
    for (let i = 0; i < 1000; i++) {}
    const t1 = performance.now();
    if (t1 - t0 > 50) report('perf');
  }
  setInterval(checkPerf, 5000);

  // Method 4: DevTools key shortcuts
  const blocked = ['F12','F11'];
  document.addEventListener('keydown', function(e) {
    if (blocked.includes(e.key)) { e.preventDefault(); report('keys'); }
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I','J','C'].includes(e.key.toUpperCase())) {
      e.preventDefault(); report('keys');
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toUpperCase() === 'U') {
      e.preventDefault(); report('keys');
    }
  });

  // Method 5: Right-click disable
  document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
})();
`;

// ─── GET /api/admin/devtool/snippet.js ───────────────────────────────────────
// Returns the frontend snippet as a JS file to be embedded in the SPA
router.get('/snippet.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'no-store');
  res.send(FRONTEND_DEVTOOL_SNIPPET);
});

module.exports = router;
module.exports.FRONTEND_DEVTOOL_SNIPPET = FRONTEND_DEVTOOL_SNIPPET;
