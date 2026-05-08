/**
 * adminAuth.js — Admin Authentication Module
 * Method: Username + Password + TOTP (Google Authenticator / Authy)
 * JWT with short expiry + refresh token rotation
 */

require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const speakeasy  = require('speakeasy');
const qrcode     = require('qrcode');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');

const router = express.Router();

// ─── Admin Schema ─────────────────────────────────────────────────────────────
const AdminSchema = new mongoose.Schema({
  username:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash:    { type: String, required: true },
  totpSecret:      { type: String, default: null },       // encrypted TOTP secret
  totpEnabled:     { type: Boolean, default: false },
  role:            { type: String, enum: ['superadmin', 'admin', 'viewer'], default: 'admin' },
  ipWhitelist:     { type: [String], default: [] },       // empty = any IP allowed
  isActive:        { type: Boolean, default: true },
  lastLogin:       { type: Date, default: null },
  lastLoginIP:     { type: String, default: null },
  failedAttempts:  { type: Number, default: 0 },
  lockedUntil:     { type: Date, default: null },
  refreshTokens:   { type: [String], default: [] },       // hashed refresh tokens
  createdAt:       { type: Date, default: Date.now },
}, { collection: 'admin_users' });

const Admin = mongoose.models.Admin || mongoose.model('Admin', AdminSchema);

// ─── Audit Log Schema ─────────────────────────────────────────────────────────
const AuditSchema = new mongoose.Schema({
  adminId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  username:  String,
  action:    String,
  ip:        String,
  userAgent: String,
  meta:      mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now },
}, { collection: 'admin_audit_logs' });

const AuditLog = mongoose.models.AuditLog || mongoose.model('AuditLog', AuditSchema);

// ─── Helpers ──────────────────────────────────────────────────────────────────
const JWT_SECRET         = process.env.ADMIN_JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.ADMIN_JWT_REFRESH_SECRET;
const TOTP_ISSUER        = process.env.TOTP_ISSUER || 'SolveMCQ Admin';

if (!JWT_SECRET || !JWT_REFRESH_SECRET) {
  console.error('[adminAuth] ADMIN_JWT_SECRET and ADMIN_JWT_REFRESH_SECRET must be set in .env');
  process.exit(1);
}

function signAccess(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '15m', algorithm: 'HS256' });
}

function signRefresh(payload) {
  return jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: '7d', algorithm: 'HS256' });
}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
}

function encryptTotpSecret(secret) {
  const key = crypto.scryptSync(process.env.TOTP_ENCRYPT_KEY || JWT_SECRET, 'salt', 32);
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return iv.toString('hex') + ':' + cipher.update(secret, 'utf8', 'hex') + cipher.final('hex');
}

function decryptTotpSecret(enc) {
  const [ivHex, encrypted] = enc.split(':');
  const key = crypto.scryptSync(process.env.TOTP_ENCRYPT_KEY || JWT_SECRET, 'salt', 32);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(ivHex, 'hex'));
  return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

async function writeAudit(adminId, username, action, req, meta = {}) {
  try {
    await AuditLog.create({
      adminId, username, action,
      ip:        getIp(req),
      userAgent: req.headers['user-agent'] || '',
      meta,
    });
  } catch (e) { /* non-blocking */ }
}

// ─── POST /login ──────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password, totp } = req.body;
  const ip = getIp(req);

  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

  try {
    const admin = await Admin.findOne({ username: username.toLowerCase().trim() });

    if (!admin || !admin.isActive) {
      await writeAudit(null, username, 'LOGIN_FAIL_NO_USER', req);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // IP whitelist check
    if (admin.ipWhitelist.length > 0 && !admin.ipWhitelist.includes(ip)) {
      await writeAudit(admin._id, username, 'LOGIN_FAIL_IP_BLOCKED', req, { ip });
      return res.status(403).json({ error: 'Access from your IP is not permitted.' });
    }

    // Account lockout
    if (admin.lockedUntil && admin.lockedUntil > new Date()) {
      const minutes = Math.ceil((admin.lockedUntil - Date.now()) / 60000);
      return res.status(423).json({ error: `Account locked. Try again in ${minutes} min.` });
    }

    // Password check
    const valid = await bcrypt.compare(password, admin.passwordHash);
    if (!valid) {
      admin.failedAttempts += 1;
      if (admin.failedAttempts >= 5) {
        admin.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 min lock
        admin.failedAttempts = 0;
      }
      await admin.save();
      await writeAudit(admin._id, username, 'LOGIN_FAIL_BAD_PASSWORD', req);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // TOTP check
    if (admin.totpEnabled) {
      if (!totp) return res.status(200).json({ requireTotp: true });
      const secret  = decryptTotpSecret(admin.totpSecret);
      const verified = speakeasy.totp.verify({
        secret, encoding: 'base32', token: totp, window: 1,
      });
      if (!verified) {
        await writeAudit(admin._id, username, 'LOGIN_FAIL_BAD_TOTP', req);
        return res.status(401).json({ error: 'Invalid TOTP code.' });
      }
    }

    // Success — reset lockout
    admin.failedAttempts = 0;
    admin.lockedUntil    = null;
    admin.lastLogin      = new Date();
    admin.lastLoginIP    = ip;

    const payload = { id: admin._id.toString(), username: admin.username, role: admin.role };
    const access  = signAccess(payload);
    const refresh = signRefresh({ id: admin._id.toString() });

    // Store hashed refresh token
    const hashedRefresh = crypto.createHash('sha256').update(refresh).digest('hex');
    admin.refreshTokens = [...(admin.refreshTokens || []).slice(-4), hashedRefresh]; // keep last 5
    await admin.save();
    await writeAudit(admin._id, username, 'LOGIN_SUCCESS', req);

    res.json({ accessToken: access, refreshToken: refresh, role: admin.role, username: admin.username });
  } catch (err) {
    console.error('[adminAuth/login]', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /refresh ────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required.' });

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const admin   = await Admin.findById(decoded.id);
    if (!admin || !admin.isActive) return res.status(401).json({ error: 'Unauthorized.' });

    const hashed = crypto.createHash('sha256').update(refreshToken).digest('hex');
    if (!admin.refreshTokens.includes(hashed)) return res.status(401).json({ error: 'Token reuse detected.' });

    // Rotate refresh token
    const newRefresh = signRefresh({ id: admin._id.toString() });
    const newHashed  = crypto.createHash('sha256').update(newRefresh).digest('hex');
    admin.refreshTokens = admin.refreshTokens.filter(t => t !== hashed).concat(newHashed);
    await admin.save();

    const payload = { id: admin._id.toString(), username: admin.username, role: admin.role };
    res.json({ accessToken: signAccess(payload), refreshToken: newRefresh });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token.' });
  }
});

// ─── POST /logout ─────────────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
      const admin   = await Admin.findById(decoded.id);
      if (admin) {
        const hashed = crypto.createHash('sha256').update(refreshToken).digest('hex');
        admin.refreshTokens = admin.refreshTokens.filter(t => t !== hashed);
        await admin.save();
      }
    } catch (_) { /* ignore */ }
  }
  res.json({ message: 'Logged out.' });
});

// ─── POST /setup-totp ─────────────────────────────────────────────────────────
router.post('/setup-totp', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Credentials required.' });

  try {
    const admin = await Admin.findOne({ username: username.toLowerCase().trim() });
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    const valid = await bcrypt.compare(password, admin.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid password.' });

    const secret = speakeasy.generateSecret({ name: `${TOTP_ISSUER} (${admin.username})`, length: 20 });
    admin.totpSecret  = encryptTotpSecret(secret.base32);
    admin.totpEnabled = false; // not yet confirmed
    await admin.save();

    const qr = await qrcode.toDataURL(secret.otpauth_url);
    res.json({ qrCode: qr, manualKey: secret.base32 });
  } catch (err) {
    res.status(500).json({ error: 'TOTP setup failed.' });
  }
});

// ─── POST /confirm-totp ───────────────────────────────────────────────────────
router.post('/confirm-totp', async (req, res) => {
  const { username, password, totp } = req.body;
  try {
    const admin = await Admin.findOne({ username: username.toLowerCase().trim() });
    if (!admin) return res.status(404).json({ error: 'Admin not found.' });
    const valid = await bcrypt.compare(password, admin.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid password.' });

    const secret   = decryptTotpSecret(admin.totpSecret);
    const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token: totp, window: 1 });
    if (!verified) return res.status(400).json({ error: 'Invalid TOTP code. Try again.' });

    admin.totpEnabled = true;
    await admin.save();
    res.json({ message: 'TOTP enabled successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'TOTP confirmation failed.' });
  }
});

// ─── POST /create-admin (superadmin only, first-run uses env secret) ──────────
router.post('/create-admin', async (req, res) => {
  const { bootstrapSecret, username, password, role } = req.body;
  if (bootstrapSecret !== process.env.ADMIN_BOOTSTRAP_SECRET) {
    return res.status(403).json({ error: 'Invalid bootstrap secret.' });
  }
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  if (password.length < 12) return res.status(400).json({ error: 'Password must be ≥ 12 characters.' });

  try {
    const existing = await Admin.findOne({ username: username.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'Username already exists.' });
    const hash  = await bcrypt.hash(password, 14);
    const admin = await Admin.create({ username: username.toLowerCase(), passwordHash: hash, role: role || 'admin' });
    await writeAudit(admin._id, username, 'ADMIN_CREATED', req, { role });
    res.status(201).json({ message: 'Admin created.', id: admin._id });
  } catch (err) {
    res.status(500).json({ error: 'Creation failed.' });
  }
});

module.exports = router;
module.exports.Admin    = Admin;
module.exports.AuditLog = AuditLog;
