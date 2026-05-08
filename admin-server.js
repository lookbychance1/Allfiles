/**
 * admin-server.js — Separate Admin Microservice
 * Hosted at: managemcq.sharepremium.in
 * Port: 4000 (separate from main backend)
 *
 * Security layers:
 *  1. Helmet (HTTP headers)
 *  2. CORS (whitelist only)
 *  3. Rate limiting (per IP + per admin)
 *  4. TOTP + JWT admin auth
 *  5. HMAC signed requests
 *  6. DevTool detection + IP ban
 *  7. Audit logging to MongoDB
 */

require('dotenv').config();
const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const rateLimit      = require('express-rate-limit');
const mongoSanitize  = require('express-mongo-sanitize');
const hpp            = require('hpp');
const compression    = require('compression');
const morgan         = require('morgan');
const mongoose       = require('mongoose');
const redis          = require('redis');
const path           = require('path');
const fs             = require('fs');

// ─── Route Modules ───────────────────────────────────────────────────────────
const adminAuthRoutes        = require('./adminAuth');
const userMgmtRoutes         = require('./userManagement');
const questionMgmtRoutes     = require('./questionManagement');
const notificationRoutes     = require('./notificationManager');
const maintenanceRoutes      = require('./systemMaintenance');
const versionRoutes          = require('./versionUpdate');
const blocklistRoutes        = require('./adminBlocklist');
const geoStatsRoutes         = require('./geoStats');
const devtoolRoutes          = require('./devtoolDetect');
const { adminAuth, auditLog } = require('./adminMiddleware');

const app  = express();
const PORT = process.env.ADMIN_PORT || 4000;

// ─── MongoDB Connection ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser:    true,
  useUnifiedTopology: true,
  maxPoolSize:        10,
}).then(() => console.log('[Admin] MongoDB connected'))
  .catch(err => { console.error('[Admin] MongoDB error:', err); process.exit(1); });

// ─── Redis Connection ─────────────────────────────────────────────────────────
const redisClient = redis.createClient({ url: process.env.REDIS_URL });
redisClient.on('error', err => console.error('[Admin] Redis error:', err));
redisClient.connect().then(() => console.log('[Admin] Redis connected'));
app.set('redis', redisClient);

// ─── Allowed Origins ──────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ADMIN_ALLOWED_ORIGINS || 'https://managemcq.sharepremium.in').split(',');

// ─── Middleware Stack ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'nonce-DYNAMIC'"],
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:      ["'self'", 'data:', 'blob:', 'https://tile.openstreetmap.org'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: ${origin} not allowed`));
  },
  methods:     ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Token', 'X-Request-ID', 'X-Timestamp'],
}));

app.use(mongoSanitize());
app.use(hpp());
app.use(compression());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ─── Access Logging ───────────────────────────────────────────────────────────
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'admin-access.log'),
  { flags: 'a' }
);
app.use(morgan('combined', { stream: accessLogStream }));

// ─── Global Rate Limiter ──────────────────────────────────────────────────────
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      200,
  message:  { error: 'Too many requests, slow down.' },
  standardHeaders: true,
  legacyHeaders:   false,
}));

// ─── Auth Rate Limiter (strict) ───────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message:  { error: 'Too many login attempts.' },
});

// ─── Public Routes (no auth) ──────────────────────────────────────────────────
app.use('/api/admin/auth',      authLimiter, adminAuthRoutes);
app.use('/api/admin/devtool',   devtoolRoutes);          // receives devtool pings

// ─── Serve Admin SPA ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'admin-public'), {
  maxAge: '1d',
  etag:   true,
}));

// ─── Protected Routes (JWT + TOTP verified) ───────────────────────────────────
app.use('/api/admin/users',        adminAuth, auditLog, userMgmtRoutes);
app.use('/api/admin/questions',    adminAuth, auditLog, questionMgmtRoutes);
app.use('/api/admin/notifications',adminAuth, auditLog, notificationRoutes);
app.use('/api/admin/maintenance',  adminAuth, auditLog, maintenanceRoutes);
app.use('/api/admin/version',      adminAuth, auditLog, versionRoutes);
app.use('/api/admin/blocklist',    adminAuth, auditLog, blocklistRoutes);
app.use('/api/admin/geo-stats',    adminAuth, geoStatsRoutes);

// ─── Health Check (internal only) ────────────────────────────────────────────
app.get('/health', (req, res) => {
  const allowedHealthIPs = (process.env.HEALTH_CHECK_IPS || '127.0.0.1').split(',');
  const ip = req.ip || req.connection.remoteAddress;
  if (!allowedHealthIPs.includes(ip)) return res.status(403).json({ error: 'Forbidden' });
  res.json({
    status:    'ok',
    uptime:    process.uptime(),
    timestamp: Date.now(),
    mongo:     mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ─── Catch-All → SPA ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-public', 'index.html'));
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[Admin Error]', err.message);
  const status = err.status || 500;
  res.status(status).json({ error: err.message || 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Admin Server] Running on port ${PORT}`);
  // Ensure logs directory exists
  if (!fs.existsSync(path.join(__dirname, 'logs'))) {
    fs.mkdirSync(path.join(__dirname, 'logs'), { recursive: true });
  }
});

module.exports = app;
