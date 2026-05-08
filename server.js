require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const jwt          = require('jsonwebtoken');
const crypto       = require('crypto');
const compression  = require('compression');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');
const fs           = require('fs');
const path         = require('path');

// ── CORS violation log (appends to cors-violations.log beside this file) ──
const CORS_LOG_PATH = path.join(__dirname, 'cors-violations.log');
function logCorsViolation(req, blockedOrigin) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
          ?? req.socket?.remoteAddress
          ?? 'unknown';
  const entry = {
    timestamp : new Date().toISOString(),
    origin    : blockedOrigin || '(no origin header)',
    ip,
    method    : req.method,
    path      : req.originalUrl || req.url,
    userAgent : req.headers['user-agent'] || '(none)',
    referer   : req.headers['referer'] || req.headers['referrer'] || '(none)',
  };
  console.warn('[CORS BLOCKED]', JSON.stringify(entry));
  fs.appendFile(CORS_LOG_PATH, JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error('[CORS LOG] Failed to write:', err.message);
  });
  // Auto-block: record violation in Redis. If threshold reached, IP gets blocked
  // (7-day temp ban first; permanent ban if re-offends within 30 days of first block).
  corsBlocklist.recordViolation(ip).then(({ nowBlocked, type }) => {
    if (nowBlocked) {
      console.warn(`[CORS BLOCKLIST] Auto-blocked ${ip} (${type}) after CORS violation threshold`);
    }
  }).catch(() => {});
}

const { getSubjectIndex, getMainSubjectIndex, loadAllData } = require('./dataLoader');
const { initRedis: initSessionRedis, createSession, fetchQuestion, fetchSectionBatch, getSectionTimer, expireSection, submitAnswer, finishSession } = require('./sessions');
const authModule  = require('./auth');
const oauthModule = require('./oauth');
const SR = require('./signedRequests');
const { initRedis: initSRRedis } = SR;
const corsBlocklist = require('./corsBlocklist');

const app = express();
const JWT_SECRET  = process.env.JWT_SECRET || 'nEetPg@SolveMCQ_2026!xKz';
const PORT        = process.env.PORT || 3000;
const MONGO_URI   = process.env.MONGO_URI || 'mongodb://localhost:27017/MCQwebData';

// ── Cookie name & options ──────────────────────────────────────────────────
const COOKIE_NAME = 'smcq_sess';
const COOKIE_OPTS = {
  httpOnly: true,          // JS cannot read this cookie — XSS-proof
  secure:   true,          // HTTPS only
  sameSite: 'none',        // cross-origin (frontend ≠ backend domain)
  maxAge:   30 * 24 * 3600 * 1000,  // 30 days in ms (matches JWT expiry)
  path:     '/'
};

// ── MongoDB ────────────────────────────────────────────────
let db = null;
async function connectMongo() {
  try {
    const client = new MongoClient(MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 50,          // max concurrent DB connections (default was 100, tuned for shared Atlas)
      minPoolSize: 5,           // keep 5 warm connections ready at all times
      waitQueueTimeoutMS: 5000, // fail fast if pool exhausted rather than hanging indefinitely
    });
    await client.connect();
    db = client.db('MCQwebData');
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('users').createIndex({ userId: 1 }, { unique: true });
    await db.collection('progress').createIndex({ userId: 1 }, { unique: true });
    await db.collection('resume').createIndex({ userId: 1 }, { unique: true });
    await db.collection('live_exam').createIndex({ userId: 1 }, { unique: true });
    // TTL index: auto-delete live_exam docs 4 hours after last update.
    // Max real exam duration is ~3.5h (210 min); 4h gives a safe buffer.
    // This is a backstop — normal deletion happens on submit/expire/clear.
    await db.collection('live_exam').createIndex({ updatedAt: 1 }, { expireAfterSeconds: 4 * 60 * 60 });
    await db.collection('topic_stats').createIndex({ userId: 1 }, { unique: true });
    await db.collection('test_reviews').createIndex({ userId: 1 }, { unique: true });
    await db.collection('users').createIndex({ phone: 1 }, { unique: true, sparse: true }); // phone is optional
    await db.collection('sessions').createIndex({ tokenHash: 1 }, { unique: true });
    await db.collection('sessions').createIndex({ userId: 1 });
    // Auto-delete expired sessions (token TTL is 30d; keep a buffer)
    await db.collection('sessions').createIndex({ createdAt: 1 }, { expireAfterSeconds: 33 * 24 * 60 * 60 });
    console.log('MongoDB connected');
  } catch (e) {
    console.warn('MongoDB unavailable - progress will not persist:', e.message);
    db = null;
  }
}

// ── Proxy trust ─────────────────────────────────────────────────────────────
// 'loopback' trusts only 127.0.0.1/::1 (Nginx on same host).
// If your proxy is on a separate host, set this to its IP/CIDR instead.
// NEVER use `true` — that lets any client spoof X-Forwarded-For.
app.set('trust proxy', 'loopback');

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(compression());  // compression after body parser

// ── CORS blocklist check — runs before everything, blocks banned IPs immediately ──
// Fails-open on Redis error (never blocks a real user due to Redis hiccup)
app.use(corsBlocklist.blocklistMiddleware);

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://mcq.sharepremium.in';



// ✅ KEEP ONLY THIS (it already handles OPTIONS correctly):
// Wrapped in a function middleware so `req` is captured in the origin closure.
app.use(function corsMiddleware(req, res, next) {
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      const allowedOrigins = (process.env.FRONTEND_URL || 'https://mcq.sharepremium.in,https://test.sharepremium.in')
        .split(',').map(s => s.trim()).filter(Boolean);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      // Log the violation with full request context (ip, path, user-agent, etc.)
      logCorsViolation(req, origin);
      return callback(new Error(`CORS policy does not allow origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-session-id', 'x-ts', 'x-nonce', 'x-sign'],
    exposedHeaders: ['x-next-key', 'x-key-rotated'],
    optionsSuccessStatus: 200  // ← add this: some Android Chrome versions reject 204 on preflight
  })(req, res, next);
});

// helmet stays after cors
app.use(helmet({ contentSecurityPolicy: false }));

// Return a clean 403 for blocked CORS requests instead of a generic 500
app.use(function corsErrorHandler(err, req, res, next) {
  if (err && err.message && err.message.startsWith('CORS policy')) {
    return res.status(403).json({ error: 'Forbidden', reason: 'CORS policy violation' });
  }
  next(err);
});

// ── Rate limiters ────────────────────────────────────────────────────────────
// keyGenerator: for authenticated routes, key on userId (post-auth middleware).
// For everything else, fall back to the verified IP address.
// This means VPN-rotation cannot bypass limits for signed-in users, and a
// spoofed X-Forwarded-For header cannot bypass the global IP cap on public routes.

function ipKey(req) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

// Authenticated routes key on userId if available, else IP.
function userOrIpKey(req) {
  return (req.user && req.user.userId) ? `uid:${req.user.userId}` : ipKey(req);
}

// Global cap: 120 req/min.  Uses IP only (auth middleware hasn't run yet for most routes).
const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  keyGenerator: ipKey,
  message: { error: 'Too many requests' },
});
app.use('/api/', globalLimiter);

// Per-user cap on authenticated read/write data endpoints: 60 req/min.
// Applied explicitly on every auth-protected route below.
const userLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  keyGenerator: userOrIpKey,
  message: { error: 'Too many requests' },
  skip: (req) => !(req.user && req.user.userId), // don't double-count unauthenticated traffic
});

// Question fetching: tighter cap to prevent bulk-scraping.
const questionLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  keyGenerator: userOrIpKey,
  message: { error: 'Slow down' },
});

// Auth endpoints: strict IP-only cap (userId not known yet).
const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  keyGenerator: ipKey,
  message: { error: 'Too many requests, slow down.' },
});

// ── Unauthenticated public API routes (config, health, oauth-enabled check) ──
// These must stay generous — real users hit them on every app open.
// 30/min per IP is plenty for legitimate use; kills scanners running at 4 req/sec.
const publicLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  keyGenerator: ipKey,
  message: { error: 'Too many requests.' },
  skip: (req) => {
    // Never rate-limit requests that already have a valid auth cookie —
    // those go through the authenticated path with userLimiter instead.
    // This skip keeps real users who are logged in completely unaffected.
    const token = req.cookies?.smcq_sess || req.headers.authorization?.split(' ')[1];
    return !!token;
  },
});

// ── Unauthenticated write routes (login, signup, OTP) ──
// authLimiter (10/min) already covers these. No additional limiter needed.

// ── Auth middleware (JWT via cookie + HMAC signed request) ──────────────────
const auth = SR.makeSignedAuthMiddleware(jwt, JWT_SECRET, COOKIE_NAME);

// ── Legacy header-only auth — used only for /api/auth/validate and /api/auth/logout
// (those two haven't received a session key yet / are clearing it)
function authCookieOnly(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME] || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    if (!req.user.userId) return res.status(401).json({ error: 'Invalid token' });
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/health', publicLimiter, (req, res) => {
  res.json({ status: 'ok', mongo: db ? 'connected' : 'unavailable', time: new Date().toISOString() });
});

// ── Session DB helpers ──────────────────────────────────────────────────────────────

/**
 * Insert a new session row whenever a token is issued.
 * Also creates the in-memory signing key for this session.
 * Returns { sessionId, sessionKey } to be sent back in the login response.
 */
async function recordSession(token, userId) {
  const tokenHash  = crypto.createHash('sha256').update(token).digest('hex');
  const sessionId  = crypto.randomBytes(16).toString('hex');
  const sessionKey = await SR.createSessionKey(sessionId);

  if (db) {
    try {
      await db.collection('sessions').insertOne({
        tokenHash,
        sessionId,
        userId,
        isActive:   true,
        createdAt:  new Date(),
        lastSeenAt: new Date()
      });
    } catch (e) {
      if (e.code !== 11000) console.error('recordSession error:', e.message);
    }
  }
  return { sessionId, sessionKey };
}

// ── Validate session (called by frontend on every app open) ─────────────────
app.post('/api/auth/validate', authLimiter, async (req, res) => {
  const token = req.cookies?.[COOKIE_NAME] || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (!payload.userId) return res.status(401).json({ error: 'Invalid token' });

  if (db) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const session   = await db.collection('sessions').findOne({ tokenHash });
    if (!session || !session.isActive) {
      res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTS, maxAge: 0 });
      return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    }
    db.collection('sessions').updateOne({ tokenHash }, { $set: { lastSeenAt: new Date() } }).catch(() => {});

    // Re-issue session signing key (fresh signing context on every app open)
    const existingSessionId = session.sessionId || crypto.randomBytes(16).toString('hex');
    const sessionKey = await SR.createSessionKey(existingSessionId);

    // Refresh cookie maxAge
    res.cookie(COOKIE_NAME, token, COOKIE_OPTS);

    try {
      const user = await db.collection('users').findOne({ userId: payload.userId });
      return res.json({
        ok:         true,
        userId:     payload.userId,
        email:      user?.email  || payload.email  || '',
        name:       user?.name   || payload.name   || '',
        phone:      user?.phone  || payload.phone  || '',
        sessionId:  existingSessionId,
        sessionKey: sessionKey
      });
    } catch {
      return res.json({ ok: true, userId: payload.userId, email: payload.email || '', name: payload.name || '', phone: payload.phone || '', sessionId: existingSessionId, sessionKey });
    }
  }

  // DB unavailable — still issue session key so requests work
  const sessionId  = crypto.randomBytes(16).toString('hex');
  const sessionKey = await SR.createSessionKey(sessionId);
  res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ ok: true, userId: payload.userId, email: payload.email || '', name: payload.name || '', phone: payload.phone || '', sessionId, sessionKey });
});

// ── Logout — invalidate session, clear cookie, delete signing key ─────────────────
app.post('/api/auth/logout', authCookieOnly, async (req, res) => {
  const token = req.cookies?.[COOKIE_NAME] || req.headers.authorization?.split(' ')[1];
  if (db && token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const session   = await db.collection('sessions').findOne({ tokenHash }, { projection: { sessionId: 1 } }).catch(() => null);
    if (session?.sessionId) await SR.deleteSessionKey(session.sessionId);
    await db.collection('sessions').updateOne({ tokenHash }, { $set: { isActive: false } }).catch(() => {});
  }
  res.clearCookie(COOKIE_NAME, { ...COOKIE_OPTS, maxAge: 0 });
  res.json({ ok: true });
});

// ── App config (feature flags) ──────────────────────────────────────────────
// PHONE_SIGNUP_SIGNIN=ON  → mobile OTP auth enabled (default)
// PHONE_SIGNUP_SIGNIN=OFF → mobile OTP auth hidden from UI and blocked on backend
// LEGACY_LOGIN=ON         → "Old User?" tab enabled (default: ON)
// LEGACY_LOGIN=OFF        → "Old User?" tab hidden from UI
const phoneAuthEnabled  = (process.env.PHONE_SIGNUP_SIGNIN || 'ON').trim().toUpperCase() !== 'OFF';
const legacyLoginEnabled = (process.env.LEGACY_LOGIN || 'ON').trim().toUpperCase() !== 'OFF';

app.get('/api/config', publicLimiter, (req, res) => {
  res.json({ phoneAuth: phoneAuthEnabled, legacyLogin: legacyLoginEnabled });
});

// ── Auth routes ─────────────────────────────────────────────────────────────

// Send OTP (signup or login)
app.post('/api/auth/send-otp', authLimiter, async (req, res) => {
  try { await authModule.handleSendOTP(req, res, db); }
  catch (e) { console.error('send-otp error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Verify OTP
app.post('/api/auth/verify-otp', authLimiter, async (req, res) => {
  try { await authModule.handleVerifyOTP(req, res); }
  catch (e) { console.error('verify-otp error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Complete signup (after OTP verified)
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try { await authModule.handleSignup(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('signup error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Login (email + password + prior OTP verification)
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try { await authModule.handleLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('login error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Reset password (forgot password flow)
app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try { await authModule.handleResetPassword(req, res, db); }
  catch (e) { console.error('reset-password error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Legacy login (old applicationNo === password users)
app.post('/api/auth/legacy-login', authLimiter, async (req, res) => {
  try { await authModule.handleLegacyLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('legacy-login error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// Migrate legacy account to email
app.post('/api/auth/migrate-email', authLimiter, async (req, res) => {
  try { await authModule.handleMigrateEmail(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('migrate-email error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// ── Phone (mobile number) auth routes ────────────────────────────────────────
// All phone routes are gated by PHONE_SIGNUP_SIGNIN env var.
// If set to OFF, every phone endpoint returns 403 so even direct API calls are blocked.
function phoneAuthGuard(req, res, next) {
  if (!phoneAuthEnabled) return res.status(403).json({ error: 'Mobile sign-in is currently disabled.' });
  next();
}

app.post('/api/auth/phone/send-otp', authLimiter, phoneAuthGuard, async (req, res) => {
  try { await authModule.handlePhoneSendOTP(req, res, db); }
  catch (e) { console.error('phone send-otp error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/auth/phone/verify-otp', authLimiter, phoneAuthGuard, async (req, res) => {
  try { await authModule.handlePhoneVerifyOTP(req, res); }
  catch (e) { console.error('phone verify-otp error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/auth/phone/signup', authLimiter, phoneAuthGuard, async (req, res) => {
  try { await authModule.handlePhoneSignup(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('phone signup error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/auth/phone/login', authLimiter, phoneAuthGuard, async (req, res) => {
  try { await authModule.handlePhoneLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('phone login error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/auth/phone/reset-password', authLimiter, phoneAuthGuard, async (req, res) => {
  try { await authModule.handlePhoneResetPassword(req, res, db); }
  catch (e) { console.error('phone reset-password error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// ── OAuth social sign-in ──────────────────────────────────
// GET  /api/auth/oauth/enabled  → returns which providers are ON
app.get('/api/auth/oauth/enabled', publicLimiter, (req, res) => {
  try { oauthModule.handleEnabledProviders(req, res); }
  catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// GET  /api/auth/oauth/url/:provider  → returns { url } to open in popup
app.get('/api/auth/oauth/url/:provider', authLimiter, (req, res) => {
  try { oauthModule.handleGetOAuthURL(req, res); }
  catch (e) { console.error('oauth-url error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/auth/oauth/callback/:provider', async (req, res) => {
  try { await oauthModule.handleOAuthCallback(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('oauth-callback error:', e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/auth/oauth/callback/:provider', express.urlencoded({ extended: true }), async (req, res) => {
  try { await oauthModule.handleOAuthCallback(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS); }
  catch (e) { console.error('oauth-callback (post) error:', e); res.status(500).json({ error: 'Server error.' }); }
});

// ── Flat subject index (legacy, kept for compatibility) ──
app.get('/api/subjects', auth, userLimiter, (req, res) => {
  // Data is static at runtime — safe to cache in the browser for 5 minutes.
  // 'private' so CDN/proxies don't share one user's response with another.
  res.set('Cache-Control', 'private, max-age=300');
  const index = getSubjectIndex();
  const result = {};
  for (const [key, data] of Object.entries(index)) {
    result[key] = {
      displayName: data.displayName,
      mainSubject: data.mainSubject,
      topics: data.topics.map(t => ({ id: t.id, name: t.name, count: t.count }))
    };
  }
  res.json(result);
});

// ── Main-subject grouped index (NEW) ──
app.get('/api/main-subjects', auth, userLimiter, (req, res) => {
  res.set('Cache-Control', 'private, max-age=300');
  res.json(getMainSubjectIndex());
});

// ── Progress persistence ──
app.get('/api/user/progress', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ progress: {} });
  try {
    const doc = await db.collection('progress').findOne({ userId: req.user.userId });
    res.json({ progress: doc?.progress || {} });
  } catch { res.json({ progress: {} }); }
});

app.post('/api/user/progress', auth, userLimiter, async (req, res) => {
  const { progress } = req.body;
  if (!db || !progress || typeof progress !== 'object') return res.json({ ok: true });
  try {
    // Use $max per dot-notation key so we never overwrite existing higher values
    // and never replace the entire progress object (which would wipe unrelated topics).
    const maxFields = { updatedAt: new Date() };
    for (const [sk, topicMap] of Object.entries(progress)) {
      if (!topicMap || typeof topicMap !== 'object') continue;
      for (const [tid, val] of Object.entries(topicMap)) {
        maxFields[`progress.${sk}.${tid}`] = typeof val === 'number' ? val : 0;
      }
    }
    await db.collection('progress').updateOne(
      { userId: req.user.userId },
      { $max: maxFields },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('progress save error:', e);
    res.json({ ok: false });
  }
});

// ── Test mode resume checkpoint ──
app.get('/api/user/resume', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ resume: null });
  try {
    const doc = await db.collection('resume').findOne({ userId: req.user.userId });
    res.json({ resume: doc?.resume || null });
  } catch { res.json({ resume: null }); }
});

app.post('/api/user/resume', auth, userLimiter, async (req, res) => {
  const { resume } = req.body;
  if (!db) return res.json({ ok: true });
  try {
    if (resume === null) {
      await db.collection('resume').deleteOne({ userId: req.user.userId });
    } else {
      await db.collection('resume').updateOne(
        { userId: req.user.userId },
        { $set: { resume, updatedAt: new Date() } },
        { upsert: true }
      );
    }
    res.json({ ok: true });
  } catch { res.json({ ok: false }); }
});

// ── Real Exam live session state (persists across app close/reopen within time window) ──
app.get('/api/user/live-exam', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ liveExam: null });
  try {
    const doc = await db.collection('live_exam').findOne({ userId: req.user.userId });
    const le = doc?.liveExam || null;
    if (le && le.startedAt && le.totalSecs) {
      const elapsed = (Date.now() - new Date(le.startedAt).getTime()) / 1000;
      if (elapsed >= le.totalSecs) {
        // Expired — clean up silently
        db.collection('live_exam').deleteOne({ userId: req.user.userId }).catch(() => {});
        return res.json({ liveExam: null });
      }
    }
    res.json({ liveExam: le });
  } catch { res.json({ liveExam: null }); }
});

app.post('/api/user/live-exam', auth, userLimiter, async (req, res) => {
  const { liveExam } = req.body;
  if (!db) return res.json({ ok: true });
  try {
    if (liveExam === null) {
      await db.collection('live_exam').deleteOne({ userId: req.user.userId });
    } else {
      await db.collection('live_exam').updateOne(
        { userId: req.user.userId },
        { $set: { liveExam, updatedAt: new Date() } },
        { upsert: true }
      );
    }
    res.json({ ok: true });
  } catch { res.json({ ok: false }); }
});

// ── Topic stats (solved/unsolved + per-question correct/incorrect/skipped) ──
// Structure in DB: { userId, stats: { "subjKey_topicId": { questions: { "0": {correct,incorrect,skipped}, ... } } } }
app.get('/api/user/topic-stats', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ stats: {} });
  try {
    const doc = await db.collection('topic_stats').findOne({ userId: req.user.userId });
    res.json({ stats: doc?.stats || {} });
  } catch { res.json({ stats: {} }); }
});

/**
 * POST /api/user/topic-stats
 * Body: { subjKey, topicId, results: [ { globalIndex, isCorrect, skipped } ] }
 * Merges per-question results into the cumulative stats.
 * For each question:
 *   - if skipped: skipped++
 *   - if correct: correct++, and if it was previously wrong decrement incorrect (to keep total = correct+incorrect+skipped = # attempts, not # appearances)
 *   - if incorrect: incorrect++
 * Actually simpler: track per-attempt result. Total questions = total unique globalIndices attempted.
 * The requirement says: "for same wrong/skipped question, if in next attempt correct/incorrect/skipped again, to be updated accordingly so that total questions remains same"
 * This means: per question, we track its CURRENT state (last known) AND the cumulative counts across all attempts.
 * Final display: x correct = count of questions whose LATEST result is correct (or cumulative correct attempts count?)
 * Re-reading: "total numbers of all previous test attempts results" — so it's cumulative counts.
 * And "total questions remains same" means total = total Q in topic (not total attempts).
 * So: x+y+z = total questions in topic, where each question contributes to exactly one bucket based on its LATEST result.
 */
app.post('/api/user/topic-stats', auth, userLimiter, async (req, res) => {
  const { subjKey, topicId, results } = req.body;
  if (!subjKey || topicId === undefined || !Array.isArray(results)) {
    return res.status(400).json({ error: 'Missing params' });
  }
  if (!db) return res.json({ ok: true });

  const statsKey = `${subjKey}_${topicId}`;

  try {
    // Use dot-notation $set per question key so we never replace
    // other topics' stats that aren't part of this submission.
    const setFields = { updatedAt: new Date() };
    for (const r of results) {
      const qKey = String(r.globalIndex);
      const newState = r.skipped ? 'skipped' : r.isCorrect ? 'correct' : 'incorrect';
      setFields[`stats.${statsKey}.questions.${qKey}.state`] = newState;
    }
    await db.collection('topic_stats').updateOne(
      { userId: req.user.userId },
      { $set: setFields },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('topic-stats error:', e);
    res.json({ ok: false });
  }
});

// ── Scheduled cleanup: nightly at 12:00 AM IST ──────────────────────────────
// Cleans up three collections:
//   1. test_reviews  — removes per-topic entries older than 24h
//   2. live_exam     — removes docs whose exam window has closed (belt-and-suspenders;
//                      the TTL index on updatedAt handles most cases automatically)
//   3. resume        — removes docs older than 7 days (stale unfinished test checkpoints)
// IST = UTC+5:30. Midnight IST = 18:30 UTC previous day.
function scheduleNightlyReviewCleanup() {
  function msUntilNext1830UTC() {
    const now  = new Date();
    const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 18, 30, 0, 0));
    if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
    return next - now;
  }

  async function cleanupOldReviews() {
    if (!db) {
      console.log('[cleanup] MongoDB unavailable — skipping nightly cleanup');
      return;
    }
    const isoNow         = new Date().toISOString();
    const cutoff24h      = new Date(Date.now() - 24 * 60 * 60 * 1000);       // 24 h ago
    const cutoff7d       = new Date(Date.now() - 7  * 24 * 60 * 60 * 1000);  // 7 days ago

    // ── 1. test_reviews: remove per-topic entries older than 24h ──────────
    let docsFixed = 0, keysRemoved = 0;
    try {
      const cursor = db.collection('test_reviews').find(
        { reviews: { $exists: true, $ne: {} } },
        { projection: { _id: 1, userId: 1, reviews: 1 } }
      );
      const bulkOps = [];
      await cursor.forEach(doc => {
        const staleKeys = Object.entries(doc.reviews || {})
          .filter(([, v]) => v && v.submittedAt && new Date(v.submittedAt) < cutoff24h)
          .map(([k]) => k);
        if (staleKeys.length === 0) return;
        const unsetFields = {};
        for (const k of staleKeys) unsetFields[`reviews.${k}`] = '';
        bulkOps.push({ updateOne: { filter: { _id: doc._id }, update: { $unset: unsetFields, $set: { updatedAt: new Date() } } } });
        docsFixed   += 1;
        keysRemoved += staleKeys.length;
      });
      if (bulkOps.length > 0) await db.collection('test_reviews').bulkWrite(bulkOps, { ordered: false });
      console.log(
        `[cleanup] ${isoNow} — test-reviews: ` +
        `${keysRemoved} stale entr${keysRemoved === 1 ? 'y' : 'ies'} removed across ${docsFixed} doc${docsFixed === 1 ? '' : 's'}`
      );
    } catch (e) {
      console.error(`[cleanup] ${isoNow} — test-reviews cleanup failed:`, e.message);
    }

    // ── 2. live_exam: remove docs whose exam window has fully elapsed ──────
    // Belt-and-suspenders alongside the TTL index on updatedAt.
    // A doc is expired when: Date.now() >= startedAt + totalSecs * 1000
    try {
      const leCursor = db.collection('live_exam').find(
        {},
        { projection: { _id: 1, userId: 1, liveExam: 1 } }
      );
      const leIds = [];
      await leCursor.forEach(doc => {
        const le = doc.liveExam;
        if (!le || !le.startedAt || !le.totalSecs) { leIds.push(doc._id); return; } // malformed — purge
        const expiresAt = new Date(le.startedAt).getTime() + le.totalSecs * 1000;
        if (Date.now() >= expiresAt) leIds.push(doc._id);
      });
      if (leIds.length > 0) {
        const { deletedCount } = await db.collection('live_exam').deleteMany({ _id: { $in: leIds } });
        console.log(`[cleanup] ${isoNow} — live_exam: ${deletedCount} expired doc${deletedCount === 1 ? '' : 's'} removed`);
      } else {
        console.log(`[cleanup] ${isoNow} — live_exam: nothing to purge`);
      }
    } catch (e) {
      console.error(`[cleanup] ${isoNow} — live_exam cleanup failed:`, e.message);
    }

    // ── 3. resume: remove docs older than 7 days ──────────────────────────
    try {
      const { deletedCount } = await db.collection('resume').deleteMany({ updatedAt: { $lt: cutoff7d } });
      console.log(`[cleanup] ${isoNow} — resume: ${deletedCount} stale doc${deletedCount === 1 ? '' : 's'} removed`);
    } catch (e) {
      console.error(`[cleanup] ${isoNow} — resume cleanup failed:`, e.message);
    }
  }

  const delay = msUntilNext1830UTC();
  const nextRunIST = new Date(Date.now() + delay).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
  console.log(`[cleanup] Nightly cleanup scheduled — next run at ${nextRunIST} IST (in ${Math.round(delay/60000)} min)`);

  setTimeout(() => {
    cleanupOldReviews();                         // first run at 12:00 AM IST
    setInterval(cleanupOldReviews, 24 * 60 * 60 * 1000); // repeat every 24h
  }, delay);
}

// ── Test reviews (last submitted result per topic, 24h TTL enforced client-side) ──
app.get('/api/user/test-reviews', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ reviews: {} });
  try {
    const doc = await db.collection('test_reviews').findOne({ userId: req.user.userId });
    res.json({ reviews: doc?.reviews || {} });
  } catch { res.json({ reviews: {} }); }
});

app.post('/api/user/test-reviews', auth, userLimiter, async (req, res) => {
  const { subjKey, topicId, results, score, timeTaken, mode } = req.body;
  if (!subjKey || topicId === undefined) return res.status(400).json({ error: 'Missing params' });
  if (!db) return res.json({ ok: true });
  try {
    const reviewKey = `${subjKey}_${topicId}`;
    await db.collection('test_reviews').updateOne(
      { userId: req.user.userId },
      {
        $set: {
          [`reviews.${reviewKey}`]: { results, score, timeTaken, mode: mode || 'test', submittedAt: new Date().toISOString() },
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('test-reviews save error:', e);
    res.json({ ok: false });
  }
});

// ── Dashboard: single endpoint replacing 4 separate startup calls ──
// Returns progress + resume + topic_stats + test_reviews in one round-trip.
// Cuts login from 6 network requests down to 3 (getConfig, getSubjects+getMainSubjects, this).
app.get('/api/user/dashboard', auth, userLimiter, async (req, res) => {
  if (!db) return res.json({ progress: {}, resume: null, stats: {}, reviews: {}, liveExam: null });
  try {
    const [prog, resume, stats, reviews, liveExamDoc] = await Promise.all([
      db.collection('progress').findOne({ userId: req.user.userId }),
      db.collection('resume').findOne({ userId: req.user.userId }),
      db.collection('topic_stats').findOne({ userId: req.user.userId }),
      db.collection('test_reviews').findOne({ userId: req.user.userId }),
      db.collection('live_exam').findOne({ userId: req.user.userId }),
    ]);
    let liveExam = liveExamDoc?.liveExam || null;
    // Server-side expiry check — don't serve a stale card to the client
    if (liveExam && liveExam.startedAt && liveExam.totalSecs) {
      const elapsed = (Date.now() - new Date(liveExam.startedAt).getTime()) / 1000;
      if (elapsed >= liveExam.totalSecs) {
        liveExam = null;
        db.collection('live_exam').deleteOne({ userId: req.user.userId }).catch(() => {});
      }
    }
    res.json({
      progress: prog?.progress || {},
      resume:   resume?.resume || null,
      stats:    stats?.stats   || {},
      reviews:  reviews?.reviews || {},
      liveExam
    });
  } catch (e) {
    console.error('dashboard error:', e);
    res.json({ progress: {}, resume: null, stats: {}, reviews: {}, liveExam: null });
  }
});

// ── Session management ──
app.post('/api/session/create', auth, userLimiter, async (req, res) => {
  const { subjKey, topicId, mode, filter = 'all' } = req.body;
  if (!subjKey || !topicId || !mode) return res.status(400).json({ error: 'Missing params' });
  if (!['real', 'test'].includes(mode)) return res.status(400).json({ error: 'Invalid mode' });
  if (!['all', 'incorrect', 'skipped'].includes(filter)) return res.status(400).json({ error: 'Invalid filter' });

  let topicStats = null;
  if ((filter === 'incorrect' || filter === 'skipped') && db) {
    try {
      const doc = await db.collection('topic_stats').findOne({ userId: req.user.userId });
      const statsKey = `${subjKey}_${topicId}`;
      topicStats = doc?.stats?.[statsKey] || null;
    } catch {}
  }

  const sessionId = await createSession(req.user.userId, subjKey, parseInt(topicId), mode, filter, topicStats);
  if (!sessionId) return res.status(404).json({ error: 'Subject/topic not found' });
  res.json({ sessionId });
});

app.get('/api/session/:sessionId/question/:index', auth, questionLimiter, async (req, res) => {
  const result = await fetchQuestion(req.params.sessionId, parseInt(req.params.index));
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.get('/api/session/:sessionId/section/:secIndex/questions', auth, userLimiter, async (req, res) => {
  const result = await fetchSectionBatch(req.params.sessionId, parseInt(req.params.secIndex));
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.get('/api/session/:sessionId/section/:secIndex/timer', auth, userLimiter, async (req, res) => {
  const result = await getSectionTimer(req.params.sessionId, parseInt(req.params.secIndex));
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.post('/api/session/:sessionId/section/:secIndex/expire', auth, userLimiter, async (req, res) => {
  const result = await expireSection(req.params.sessionId, parseInt(req.params.secIndex));
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.post('/api/session/:sessionId/answer', auth, userLimiter, async (req, res) => {
  const result = await submitAnswer(req.params.sessionId, req.body.index, req.body.selected);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

app.post('/api/session/:sessionId/finish', auth, userLimiter, async (req, res) => {
  const result = await finishSession(req.params.sessionId);
  if (result.error) return res.status(400).json(result);
  res.json(result);
});

// ── Admin: CORS blocklist management ─────────────────────────────────────────
// Secured by ADMIN_SECRET env var — set a long random string in your .env.
// Usage:
//   List all blocked IPs:  GET  /api/admin/blocklist          (Header: x-admin-secret: YOUR_SECRET)
//   Unblock an IP:         POST /api/admin/blocklist/unblock  (Body: { ip: "1.2.3.4" })
//   Permanent ban:         POST /api/admin/blocklist/ban      (Body: { ip: "1.2.3.4", reason: "..." })
//
// HOW TO UNBLOCK FROM CLI (without HTTP):
//   redis-cli DEL cors:blocked:1.2.3.4 cors:violations:1.2.3.4 cors:first_block:1.2.3.4
//
function adminAuth(req, res, next) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) return res.status(503).json({ error: 'Admin secret not configured.' });
  const provided = req.headers['x-admin-secret'] || req.query.secret;
  if (!provided || provided !== secret) {
    console.warn(`[ADMIN] Unauthorized blocklist access attempt from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  next();
}

app.get('/api/admin/blocklist', adminAuth, async (req, res) => {
  const list = await corsBlocklist.listBlocked();
  res.json({ blocked: list, count: list.length, lru: corsBlocklist.lruStats() });
});

app.post('/api/admin/blocklist/unblock', adminAuth, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const result = await corsBlocklist.unblockIp(ip);
  if (result.ok) {
    console.log(`[ADMIN] ${req.ip} unblocked ${ip}`);
    res.json({ ok: true, message: `${ip} has been unblocked.` });
  } else {
    res.status(500).json({ ok: false, error: result.error });
  }
});

app.post('/api/admin/blocklist/ban', adminAuth, async (req, res) => {
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const result = await corsBlocklist.permanentBan(ip, reason || 'manual-admin');
  if (result.ok) {
    console.log(`[ADMIN] ${req.ip} permanently banned ${ip} — reason: ${reason || 'manual'}`);
    res.json({ ok: true, message: `${ip} has been permanently banned.` });
  } else {
    res.status(500).json({ ok: false, error: result.error });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

(async () => {
  await initSRRedis();
  await initSessionRedis();
  await corsBlocklist.initRedis();   // CORS blocklist Redis connection
  await connectMongo();
  loadAllData();
  scheduleNightlyReviewCleanup();
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`SolveMCQ backend running on port ${PORT}`);
  });
})();
