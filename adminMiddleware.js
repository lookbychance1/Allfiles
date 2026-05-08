/**
 * adminMiddleware.js — Security Middleware Stack
 * - JWT verification
 * - Role-based access control
 * - Request signing verification
 * - Audit logging
 * - Suspicious activity detection
 */

require('dotenv').config();
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const mongoose = require('mongoose');

const JWT_SECRET = process.env.ADMIN_JWT_SECRET;

// ─── Audit Log Schema (shared) ────────────────────────────────────────────────
const AuditSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  username:  String,
  action:    String,
  method:    String,
  path:      String,
  ip:        String,
  userAgent: String,
  statusCode:Number,
  duration:  Number,
  meta:      mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_audit_logs' });

const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditSchema);

// ─── DevTool Incident Schema ──────────────────────────────────────────────────
const DevToolIncidentSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', default: null },
  username:  { type: String, default: 'unknown' },
  ip:        String,
  userAgent: String,
  method:    { type: String, enum: ['resize', 'debugger', 'perf', 'keys', 'beacon'] },
  sessionId: String,
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_devtool_incidents' });

const DevToolIncident = mongoose.models.DevToolIncident || mongoose.model('DevToolIncident', DevToolIncidentSchema);

// ─── Helper: extract IP ───────────────────────────────────────────────────────
function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
}

// ─── Middleware: adminAuth ────────────────────────────────────────────────────
async function adminAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header missing.' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.admin = decoded; // { id, username, role }
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired.', code: 'TOKEN_EXPIRED' });
    return res.status(401).json({ error: 'Invalid token.' });
  }
}

// ─── Middleware: requireRole ──────────────────────────────────────────────────
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.admin) return res.status(401).json({ error: 'Not authenticated.' });
    if (!roles.includes(req.admin.role)) {
      return res.status(403).json({ error: `Requires role: ${roles.join(' or ')}.` });
    }
    next();
  };
}

// ─── Middleware: auditLog ─────────────────────────────────────────────────────
function auditLog(req, res, next) {
  const start = Date.now();
  const origJson = res.json.bind(res);

  res.json = function (body) {
    const duration = Date.now() - start;
    AuditLog.create({
      adminId:    req.admin?.id  || null,
      username:   req.admin?.username || 'unknown',
      action:     `${req.method} ${req.path}`,
      method:     req.method,
      path:       req.path,
      ip:         getIp(req),
      userAgent:  req.headers['user-agent'] || '',
      statusCode: res.statusCode,
      duration,
      meta:       req.method !== 'GET' ? sanitizeMeta(req.body) : {},
    }).catch(() => {});
    return origJson(body);
  };

  next();
}

// Strip sensitive fields from audit body
function sanitizeMeta(body) {
  if (!body || typeof body !== 'object') return {};
  const safe = { ...body };
  ['password', 'passwordHash', 'token', 'secret', 'totp', 'refreshToken'].forEach(k => { delete safe[k]; });
  return safe;
}

// ─── Middleware: requestSignature ─────────────────────────────────────────────
// Optional layer: frontend must send X-Request-ID + X-Timestamp + X-Signature
// Signature = HMAC-SHA256(adminId + requestId + timestamp, ADMIN_SIGN_SECRET)
function requestSignature(req, res, next) {
  if (!process.env.ADMIN_SIGN_SECRET) return next(); // skip if not configured

  const reqId  = req.headers['x-request-id'];
  const ts     = req.headers['x-timestamp'];
  const sig    = req.headers['x-signature'];

  if (!reqId || !ts || !sig) return res.status(400).json({ error: 'Missing request signature headers.' });

  // Reject stale requests (>2 min)
  if (Math.abs(Date.now() - Number(ts)) > 120_000) {
    return res.status(400).json({ error: 'Request timestamp too old.' });
  }

  const expected = crypto
    .createHmac('sha256', process.env.ADMIN_SIGN_SECRET)
    .update(`${req.admin?.id || ''}:${reqId}:${ts}`)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) {
    return res.status(403).json({ error: 'Invalid request signature.' });
  }

  next();
}

// ─── Middleware: devtoolBlock ─────────────────────────────────────────────────
// Checks Redis for devtool incidents for this session; blocks if threshold exceeded
async function devtoolBlock(req, res, next) {
  const redis = req.app.get('redis');
  if (!redis) return next();

  const adminId = req.admin?.id;
  if (!adminId) return next();

  const key   = `devtool:block:${adminId}`;
  const count = await redis.get(key);

  if (count && parseInt(count) >= 3) {
    // Log the blocked access attempt
    await DevToolIncident.create({
      adminId,
      username:  req.admin.username,
      ip:        getIp(req),
      userAgent: req.headers['user-agent'],
      method:    'beacon',
      sessionId: req.headers['x-session-id'] || '',
    }).catch(() => {});
    return res.status(403).json({ error: 'Dashboard access revoked: DevTools detected.', code: 'DEVTOOL_BLOCKED' });
  }

  next();
}

module.exports = { adminAuth, requireRole, auditLog, requestSignature, devtoolBlock, DevToolIncident, AuditLog };
