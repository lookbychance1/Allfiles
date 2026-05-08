/**
 * auth.js — Email + OTP + Password authentication module
 * - Allowed domains: gmail.com, outlook.com, hotmail.com, yahoo.com, rediffmail.com
 * - 6-digit random OTP, 10 min expiry, max 5 attempts
 * - Password: min 8 chars, must have uppercase, lowercase, digit; blocks common passwords
 * - Uses nodemailer with SMTP (configure via .env)
 */

const crypto = require('crypto');
const nodemailer = require('nodemailer');

// ── Allowed email domains ─────────────────────────────────
const ALLOWED_DOMAINS = [
  'gmail.com',
  'outlook.com',
  'hotmail.com',
  'yahoo.com',
  'rediffmail.com'
];

// ── Common/weak passwords blocklist ──────────────────────
const COMMON_PASSWORDS = new Set([
  'Password1', 'Password123', 'Passw0rd', 'Admin123', 'Welcome1',
  'Qwerty123', 'Abc12345', 'Letmein1', 'Monkey123', 'Dragon123',
  'Master123', 'Hello123', 'Shadow123', 'Superman1', 'Batman123',
  'Test1234', 'User1234', 'Login123', 'Change123', 'Summer23',
  'Winter23', 'Spring23', 'Autumn23', 'India123', 'Neet2024',
  'Neet2025', 'Neet2026', 'Doctor1', 'Medical1', 'Mbbs1234'
]);

// ── In-memory OTP store: email → { otp, expiresAt, attempts, verified } ──
const otpStore = new Map();
const OTP_TTL = 10 * 60 * 1000;   // 10 minutes
const MAX_OTP_ATTEMPTS = 5;

// ── Nodemailer transporter ────────────────────────────────
let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST   || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
  return transporter;
}

// ── Helpers ───────────────────────────────────────────────

function normalizeEmail(email) {
  return (email || '').toLowerCase().trim();
}

function validateEmailDomain(email) {
  const e = normalizeEmail(email);
  // Basic format check
  const parts = e.split('@');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  const [local, domain] = parts;
  // local part: no weird chars
  if (!/^[a-z0-9._%+\-]+$/.test(local)) return false;
  // domain must be in allowed list
  return ALLOWED_DOMAINS.includes(domain);
}

/**
 * Validate password strength.
 * Returns { ok: true } or { ok: false, reason: string }
 */
function validatePassword(password) {
  if (typeof password !== 'string') return { ok: false, reason: 'Password must be a string.' };
  if (password.length < 8) return { ok: false, reason: 'Password must be at least 8 characters long.' };
  if (password.length > 72) return { ok: false, reason: 'Password too long (max 72 characters).' };
  if (!/[A-Z]/.test(password)) return { ok: false, reason: 'Password must contain at least one uppercase letter.' };
  if (!/[a-z]/.test(password)) return { ok: false, reason: 'Password must contain at least one lowercase letter.' };
  if (!/[0-9]/.test(password)) return { ok: false, reason: 'Password must contain at least one number.' };
  // Check against common passwords (case-insensitive)
  if (COMMON_PASSWORDS.has(password) || COMMON_PASSWORDS.has(
    password.charAt(0).toUpperCase() + password.slice(1).toLowerCase()
  )) {
    return { ok: false, reason: 'Password is too common. Please choose a more unique password.' };
  }
  return { ok: true };
}

/** Generate a cryptographically secure 6-digit OTP */
function generateOTP() {
  const num = crypto.randomInt(100000, 999999);
  return String(num);
}

/** Hash password with bcrypt-like PBKDF2 (no extra deps) */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const h = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash));
}

/** Clean up expired OTPs from memory */
function pruneExpiredOTPs() {
  const now = Date.now();
  for (const [key, val] of otpStore.entries()) {
    if (val.expiresAt < now) otpStore.delete(key);
  }
}

setInterval(pruneExpiredOTPs, 5 * 60 * 1000);

// ── Send OTP email ────────────────────────────────────────
async function sendOTPEmail(email, otp, isSignup) {
  const action = isSignup ? 'Sign Up' : 'Sign In';
  const appName = process.env.APP_NAME || 'PracticeMCQ';
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;

  const digits = String(otp).split('').map(d =>
    `<td style="width:44px;height:54px;background:#1e3a8a;color:#ffffff;font-size:26px;font-weight:700;text-align:center;vertical-align:middle;border-radius:8px;padding:0">${d}</td>`
  ).join('<td style="width:8px"></td>');

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${appName} Verification Code</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0">

      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#1e3a8a 0%,#2563eb 100%);padding:36px 40px 30px;text-align:center">
        <div style="font-size:22px;font-weight:700;color:#ffffff;letter-spacing:-0.5px;margin:0 0 4px">🎯 ${appName}</div>
        <div style="font-size:13px;color:#bfdbfe;margin:0">NEET PG &middot; INICET &middot; UPSC CMS</div>
      </td></tr>

      <!-- Body -->
      <tr><td style="padding:36px 40px 32px">
        <p style="font-size:17px;font-weight:600;color:#1e293b;margin:0 0 8px">Verify your email address</p>
        <p style="font-size:14px;color:#64748b;line-height:1.6;margin:0 0 28px">
          You requested a verification code to complete your <strong>${action}</strong> on ${appName}.<br>Use the code below &mdash; it&rsquo;s valid for <strong>10 minutes</strong>.
        </p>

        <!-- OTP block -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8faff;border:2px solid #dbeafe;border-radius:12px;margin-bottom:28px">
          <tr><td style="padding:22px 24px 18px;text-align:center">
            <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;color:#3b82f6;text-transform:uppercase;margin-bottom:16px">Your verification code</div>
            <table cellpadding="0" cellspacing="0" style="margin:0 auto">
              <tr>${digits}</tr>
            </table>
            <div style="font-size:12px;color:#94a3b8;margin-top:14px">Expires in <strong style="color:#ef4444">10 minutes</strong></div>
          </td></tr>
        </table>

        <!-- Divider -->
        <hr style="border:none;border-top:1px solid #f1f5f9;margin:0 0 20px"/>

        <!-- Security tips -->
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:12px">
          <tr>
            <td width="36" valign="top" style="padding-top:2px">
              <div style="width:28px;height:28px;background:#dcfce7;border-radius:50%;text-align:center;line-height:28px;font-size:14px">🔒</div>
            </td>
            <td style="font-size:13px;color:#475569;line-height:1.5;padding-left:12px">
              <strong>Never share this code.</strong> ${appName} will never ask for your OTP over call, chat, or email.
            </td>
          </tr>
        </table>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px">
          <tr>
            <td width="36" valign="top" style="padding-top:2px">
              <div style="width:28px;height:28px;background:#fef9c3;border-radius:50%;text-align:center;line-height:28px;font-size:14px">⏱</div>
            </td>
            <td style="font-size:13px;color:#475569;line-height:1.5;padding-left:12px">
              If the code expires, go back to the app and click <strong>Resend code</strong> to get a fresh one.
            </td>
          </tr>
        </table>

        <!-- Ignore note -->
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr><td style="background:#fff7ed;border-left:3px solid #fb923c;padding:12px 16px;border-radius:0 8px 8px 0;font-size:12px;color:#9a3412;line-height:1.5">
            <strong>&#9888; Didn&rsquo;t request this?</strong> Someone may have entered your email by mistake. You can safely ignore this email &mdash; no account has been created.
          </td></tr>
        </table>
      </td></tr>

      <!-- Footer -->
      <tr><td style="background:#f8fafc;border-top:1px solid #f1f5f9;padding:20px 40px;text-align:center">
        <p style="font-size:11px;color:#94a3b8;margin:3px 0"><strong>${appName}</strong> &middot; Medical Entrance MCQ Practice Platform</p>
        <p style="font-size:11px;color:#94a3b8;margin:3px 0">NEET PG &middot; INICET &middot; UPSC CMS</p>
        <p style="font-size:11px;color:#cbd5e1;margin:10px 0 0">&copy; ${new Date().getFullYear()} ${appName}</p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>`;

  await getTransporter().sendMail({
    from: `"${appName}" <${from}>`,
    to: email,
    subject: `${otp} — Your ${appName} verification code`,
    text: `Your ${appName} verification code is: ${otp}\n\nThis code expires in 10 minutes. Do not share it.`,
    html
  });
}

// ── Exported route handlers ───────────────────────────────

/**
 * POST /api/auth/send-otp
 * Body: { email, purpose: 'signup' | 'login' }
 */
async function handleSendOTP(req, res, db) {
  const { email: rawEmail, purpose } = req.body;
  const email = normalizeEmail(rawEmail);

  if (!email || !purpose) return res.status(400).json({ error: 'Missing email or purpose.' });
  if (!['signup', 'login'].includes(purpose)) return res.status(400).json({ error: 'Invalid purpose.' });

  if (!validateEmailDomain(email)) {
    return res.status(400).json({
      error: `Only Gmail, Outlook, Yahoo, and Rediffmail addresses are allowed.`
    });
  }

  // Rate-limit: if OTP was sent < 60s ago, block resend
  const existing = otpStore.get(email);
  if (existing && existing.sentAt && (Date.now() - existing.sentAt) < 60000) {
    const wait = Math.ceil((60000 - (Date.now() - existing.sentAt)) / 1000);
    return res.status(429).json({ error: `Please wait ${wait}s before requesting a new code.` });
  }

  // For login: check user exists
  if (purpose === 'login' && db) {
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.status(404).json({ error: 'No account found for this email. Please sign up first.' });
  }

  // For signup: check user NOT already registered
  if (purpose === 'signup' && db) {
    const user = await db.collection('users').findOne({ email });
    if (user) return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
  }

  const otp = generateOTP();
  otpStore.set(email, {
    otp,
    purpose,
    expiresAt: Date.now() + OTP_TTL,
    sentAt: Date.now(),
    attempts: 0,
    verified: false
  });

  try {
    await sendOTPEmail(email, otp, purpose === 'signup');
    res.json({ ok: true, message: `Verification code sent to ${email}` });
  } catch (err) {
    console.error('Email send error:', err.message);
    otpStore.delete(email);
    res.status(500).json({ error: 'Failed to send verification email. Please check the address and try again.' });
  }
}

/**
 * POST /api/auth/verify-otp
 * Body: { email, otp }
 * Returns { verified: true } — client then proceeds to set password (signup) or login
 */
async function handleVerifyOTP(req, res) {
  const { email: rawEmail, otp } = req.body;
  const email = normalizeEmail(rawEmail);

  if (!email || !otp) return res.status(400).json({ error: 'Missing email or code.' });

  const record = otpStore.get(email);
  if (!record) return res.status(400).json({ error: 'No verification code found. Please request a new one.' });
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Verification code expired. Please request a new one.' });
  }
  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    otpStore.delete(email);
    return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
  }

  record.attempts++;
  if (record.otp !== String(otp).trim()) {
    const left = MAX_OTP_ATTEMPTS - record.attempts;
    return res.status(400).json({ error: `Incorrect code. ${left} attempt${left === 1 ? '' : 's'} remaining.` });
  }

  // Mark as verified (so signup/login step can trust it happened)
  record.verified = true;
  res.json({ ok: true, verified: true, purpose: record.purpose });
}

/**
 * POST /api/auth/signup
 * Body: { email, otp, password, name }
 */
async function handleSignup(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { email: rawEmail, otp, password, name: rawName } = req.body;
  const email = normalizeEmail(rawEmail);
  const name = (rawName || '').trim();

  if (!email || !otp || !password) return res.status(400).json({ error: 'Missing required fields.' });
  if (!name) return res.status(400).json({ error: 'Please enter your name.' });
  if (name.length > 60) return res.status(400).json({ error: 'Name is too long (max 60 characters).' });

  // Re-verify OTP inline (trust-but-verify)
  const record = otpStore.get(email);
  if (!record || !record.verified || record.purpose !== 'signup') {
    return res.status(400).json({ error: 'Email not verified. Please complete OTP verification first.' });
  }
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Verification session expired. Please start over.' });
  }
  if (record.otp !== String(otp).trim()) {
    return res.status(400).json({ error: 'OTP mismatch. Please start over.' });
  }

  // Validate password
  const pwCheck = validatePassword(password);
  if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.reason });

  if (!db) return res.status(503).json({ error: 'Database unavailable. Please try again later.' });

  // Check duplicate
  const exists = await db.collection('users').findOne({ email });
  if (exists) return res.status(409).json({ error: 'Account already exists. Please sign in.' });

  const passwordHash = hashPassword(password);
  const userId = crypto.randomBytes(8).toString('hex'); // internal user ID
  const now = new Date();

  await db.collection('users').insertOne({
    email,
    userId,
    name,
    passwordHash,
    emailVerified: true,
    createdAt: now,
    lastLoginAt: now
  });

  otpStore.delete(email);

  const token = jwt.sign({ userId, email, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, userId) || {};
  if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ token, userId, email, name, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
}

/**
 * POST /api/auth/login
 * Body: { email, password }
 * OTP is NOT required for login — only required at first signup.
 * If the user's email is flagged emailVerified=false, OTP is still enforced.
 */
async function handleLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { email: rawEmail, otp, password } = req.body;
  const email = normalizeEmail(rawEmail);

  if (!email || !password) return res.status(400).json({ error: 'Missing email or password.' });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  const user = await db.collection('users').findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

  // Verify password
  let pwOk = false;
  try { pwOk = verifyPassword(password, user.passwordHash); } catch {}
  if (!pwOk) return res.status(401).json({ error: 'Invalid email or password.' });

  // If email is explicitly unverified (legacy flag), enforce OTP
  if (user.emailVerified === false) {
    const record = otpStore.get(email);
    if (!record || !record.verified || record.purpose !== 'login') {
      return res.status(403).json({ error: 'Your email is not verified. Please complete OTP verification.', requiresOTP: true });
    }
    if (Date.now() > record.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ error: 'Verification session expired.' });
    }
    otpStore.delete(email);
    // Mark as verified going forward
    await db.collection('users').updateOne({ email }, { $set: { emailVerified: true } });
  }

  await db.collection('users').updateOne({ email }, { $set: { lastLoginAt: new Date() } });

  const name = user.name || '';
  const token = jwt.sign({ userId: user.userId, email, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, user.userId) || {};
  if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ token, userId: user.userId, email, name, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
}

/**
 * POST /api/auth/reset-password
 * Body: { email, otp, newPassword }
 * OTP must be verified with purpose='login'
 */
async function handleResetPassword(req, res, db) {
  const { email: rawEmail, otp, newPassword } = req.body;
  const email = normalizeEmail(rawEmail);

  if (!email || !otp || !newPassword) return res.status(400).json({ error: 'Missing fields.' });

  const record = otpStore.get(email);
  if (!record || !record.verified) return res.status(400).json({ error: 'Email not verified.' });
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Verification expired.' });
  }
  if (record.otp !== String(otp).trim()) return res.status(400).json({ error: 'OTP mismatch.' });

  const pwCheck = validatePassword(newPassword);
  if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.reason });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  const passwordHash = hashPassword(newPassword);
  const result = await db.collection('users').updateOne({ email }, { $set: { passwordHash, updatedAt: new Date() } });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Account not found.' });

  otpStore.delete(email);
  res.json({ ok: true, message: 'Password updated successfully.' });
}

/**
 * POST /api/auth/legacy-login
 * Old-style login: applicationNo === password
 * Returns { needsEmailMigration: true, migrationToken } if no email linked yet,
 * or a full JWT if migration was already completed.
 */
async function handleLegacyLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { applicationNo, password } = req.body;
  if (!applicationNo || !password) return res.status(400).json({ error: 'Missing fields.' });

  const appNo = applicationNo.trim();
  const pass  = password.trim();

  // Original validation: appNo === password, length 6-20
  if (appNo !== pass) return res.status(401).json({ error: 'Invalid application number or password.' });
  if (appNo.length < 6 || appNo.length > 20) return res.status(401).json({ error: 'Invalid application number format.' });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  // Check if this user already completed migration (has a users doc with email)
  const existingUser = await db.collection('users').findOne({ userId: appNo });
  if (existingUser && existingUser.email) {
    // Migration already done — issue full token
    await db.collection('users').updateOne({ userId: appNo }, { $set: { lastLoginAt: new Date() } });
    const name = existingUser.name || '';
    const token = jwt.sign({ userId: appNo, email: existingUser.email, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
    let sessInfo = {};
    if (recordSession) sessInfo = await recordSession(token, appNo) || {};
    if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
    return res.json({ token, userId: appNo, email: existingUser.email, name, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
  }

  // No email yet — issue a short-lived migration token
  const migrationToken = jwt.sign(
    { userId: appNo, migrationPending: true },
    JWT_SECRET,
    { expiresIn: '30m' }
  );
  res.json({ needsEmailMigration: true, migrationToken, userId: appNo });
}

/**
 * POST /api/auth/migrate-email
 * Links an email (after OTP verification) to a legacy applicationNo account.
 * Body: { migrationToken, email, otp, password }
 * - migrationToken: short-lived JWT from legacy-login
 * - email: new email to link
 * - otp: verified OTP for that email
 * - password: new proper password (validated for strength)
 */
async function handleMigrateEmail(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { migrationToken, email: rawEmail, otp, password, name: rawName } = req.body;
  if (!migrationToken || !rawEmail || !otp || !password) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  const name = (rawName || '').trim().slice(0, 60);

  // Verify migration token
  let payload;
  try {
    payload = jwt.verify(migrationToken, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Migration session expired. Please sign in again.' });
  }
  if (!payload.migrationPending) return res.status(400).json({ error: 'Invalid migration token.' });

  const userId = payload.userId;
  const email  = normalizeEmail(rawEmail);

  if (!validateEmailDomain(email)) {
    return res.status(400).json({ error: 'Only Gmail, Outlook, Yahoo, and Rediffmail addresses are allowed.' });
  }

  // Verify OTP was completed for this email with purpose='signup'
  const record = otpStore.get(email);
  if (!record || !record.verified || record.purpose !== 'signup') {
    return res.status(400).json({ error: 'Email not verified. Please complete OTP verification.' });
  }
  if (Date.now() > record.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Verification expired. Please request a new code.' });
  }
  if (record.otp !== String(otp).trim()) {
    return res.status(400).json({ error: 'OTP mismatch. Please start over.' });
  }

  // Validate new password
  const pwCheck = validatePassword(password);
  if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.reason });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  // Check email not already taken by another account
  const emailTaken = await db.collection('users').findOne({ email, userId: { $ne: userId } });
  if (emailTaken) return res.status(409).json({ error: 'This email is already linked to another account.' });

  const passwordHash = hashPassword(password);
  const now = new Date();

  // Upsert: create users doc if not exists, or update existing legacy stub
  await db.collection('users').updateOne(
    { userId },
    {
      $set:         { email, passwordHash, name, migratedAt: now, lastLoginAt: now },
      $setOnInsert: { userId, createdAt: now }
    },
    { upsert: true }
  );

  otpStore.delete(email);

  // Issue full token — userId unchanged so all existing data stays linked
  const token = jwt.sign({ userId, email, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, userId) || {};
  if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ token, userId, email, name, migrated: true, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
}

// ═══════════════════════════════════════════════════════════
// PHONE (MOBILE) OTP AUTH
// Supported SMS providers (set SMS_PROVIDER in .env):
//   msg91      → default, best for India, requires DLT template
//   fast2sms   → cheapest Indian option, no DLT needed for dev
//   twilio     → global fallback, most reliable
// ═══════════════════════════════════════════════════════════

// ── In-memory OTP store for phone (separate from email store) ──
const phoneOtpStore = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of phoneOtpStore.entries()) {
    if (v.expiresAt < now) phoneOtpStore.delete(k);
  }
}, 5 * 60 * 1000);

/** Normalize Indian mobile number → +91XXXXXXXXXX */
function normalizePhone(raw) {
  let p = (raw || '').toString().replace(/\D/g, '');
  if (p.startsWith('91') && p.length === 12) p = p.slice(2);
  if (p.length === 10) return '+91' + p;
  return null; // invalid
}

function validatePhone(raw) {
  const p = normalizePhone(raw);
  if (!p) return false;
  // Indian mobile: starts with 6-9
  return /^\+91[6-9]\d{9}$/.test(p);
}

/**
 * Send OTP via SMS.
 * Set SMS_PROVIDER in .env to choose provider:
 *   SMS_PROVIDER=msg91       → MSG91  (default, best for India)
 *   SMS_PROVIDER=fast2sms    → Fast2SMS (cheapest Indian option, no DLT needed for dev)
 *   SMS_PROVIDER=twilio      → Twilio  (global, reliable)
 */
async function sendOTPSms(phone, otp) {
  const appName  = process.env.APP_NAME || 'PracticeMCQ';
  const provider = (process.env.SMS_PROVIDER || 'msg91').toLowerCase();
  const https    = require('https');

  // ── helper: make a simple HTTPS request and return parsed JSON ──
  function httpsRequest(options, body) {
    return new Promise((resolve, reject) => {
      const req = https.request(options, res => {
        let raw = '';
        res.on('data', d => raw += d);
        res.on('end', () => {
          let json;
          try { json = JSON.parse(raw); } catch { json = { _raw: raw }; }
          if (res.statusCode >= 400) {
            reject(new Error(json.message || json.error || json.message || `HTTP ${res.statusCode}`));
          } else {
            resolve(json);
          }
        });
      });
      req.on('error', reject);
      if (body) req.write(body);
      req.end();
    });
  }

  if (provider === 'fast2sms') {
    // ── Fast2SMS ─────────────────────────────────────────────
    // Cheapest Indian SMS provider (~₹0.06–0.10/SMS).
    // No DLT registration needed for OTP category during development.
    // Setup:
    //   1. Sign up at fast2sms.com
    //   2. Go to Dev API → copy your API key
    //   3. For production use "Quick SMS" or register a DLT template
    // .env: FAST2SMS_API_KEY
    // Optional: FAST2SMS_SENDER_ID (default: FSTSMS), FAST2SMS_LANGUAGE (default: english)
    const apiKey   = process.env.FAST2SMS_API_KEY;
    if (!apiKey) throw new Error('Fast2SMS not configured. Set FAST2SMS_API_KEY in .env');
    const message  = `Your ${appName} verification code is ${otp}. Valid for 10 minutes. Do not share with anyone.`;
    const numbers  = phone.replace('+91', ''); // Fast2SMS wants 10-digit without country code
    const payload  = JSON.stringify({
      route:    'otp',           // use 'otp' route for OTP messages (cheaper, faster)
      variables_values: otp,     // OTP route requires this field
      flash:    0,
      numbers
    });
    const json = await httpsRequest({
      hostname: 'www.fast2sms.com',
      path:     '/dev/bulkV2',
      method:   'POST',
      headers:  {
        'authorization': apiKey,
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'cache-control': 'no-cache'
      }
    }, payload);
    // Fast2SMS returns { return: true, request_id: '...' } on success
    if (json.return === false) {
      throw new Error(
        Array.isArray(json.message) ? json.message.join(', ') : (json.message || 'Fast2SMS error')
      );
    }

  } else if (provider === 'twilio') {
    // ── Twilio ───────────────────────────────────────────────
    // Most reliable, works globally. ~₹0.45–0.70/SMS to India.
    // Setup:
    //   1. Sign up at twilio.com → get Account SID, Auth Token
    //   2. Buy an SMS-capable number (or use Alphanumeric Sender ID in supported regions)
    // .env: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken  = process.env.TWILIO_AUTH_TOKEN;
    const from       = process.env.TWILIO_FROM;
    if (!accountSid || !authToken || !from) {
      throw new Error('Twilio not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM in .env');
    }
    const body = `Your ${appName} verification code is ${otp}. Valid for 10 minutes. Do not share.`;
    const data = new URLSearchParams({ To: phone, From: from, Body: body }).toString();
    await httpsRequest({
      hostname: 'api.twilio.com',
      path:     `/2010-04-01/Accounts/${accountSid}/Messages.json`,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data),
        'Authorization':  'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64')
      }
    }, data);

  } else {
    // ── MSG91 (default) ──────────────────────────────────────
    // Best balance of price (~₹0.10–0.15/SMS) and deliverability for India.
    // Requires DLT-registered template (mandatory for Indian SMS since 2021).
    // Setup:
    //   1. Sign up at msg91.com
    //   2. Register sender ID + DLT template at your telecom provider
    //   3. In MSG91: SMS → OTP → create template using ##OTP## as the variable
    //   4. Copy Auth Key from msg91.com → Dashboard → API
    // .env: MSG91_AUTH_KEY, MSG91_TEMPLATE_ID
    // Optional: MSG91_SENDER_ID (default: OTPSMS — must match DLT registration)
    const authKey    = process.env.MSG91_AUTH_KEY;
    const templateId = process.env.MSG91_TEMPLATE_ID;
    if (!authKey || !templateId) {
      throw new Error('MSG91 not configured. Set MSG91_AUTH_KEY and MSG91_TEMPLATE_ID in .env');
    }
    const senderId = process.env.MSG91_SENDER_ID || 'OTPSMS';
    const payload  = JSON.stringify({
      template_id: templateId,
      mobile:      phone.replace('+', ''), // MSG91 expects 91XXXXXXXXXX (no +)
      authkey:     authKey,
      otp:         String(otp),
      sender:      senderId
    });
    const json = await httpsRequest({
      hostname: 'control.msg91.com',
      path:     '/api/v5/otp',
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
    }, payload);
    if (json.type === 'error') throw new Error(json.message || 'MSG91 error');
  }
}

/**
 * POST /api/auth/phone/send-otp
 * Body: { phone, purpose: 'signup' | 'login' }
 */
async function handlePhoneSendOTP(req, res, db) {
  const { phone: rawPhone, purpose } = req.body;
  if (!rawPhone || !purpose) return res.status(400).json({ error: 'Missing phone or purpose.' });
  if (!['signup', 'login'].includes(purpose)) return res.status(400).json({ error: 'Invalid purpose.' });

  const phone = normalizePhone(rawPhone);
  if (!phone || !validatePhone(rawPhone)) {
    return res.status(400).json({ error: 'Enter a valid 10-digit Indian mobile number.' });
  }

  // Rate-limit: 60s between sends
  const existing = phoneOtpStore.get(phone);
  if (existing && existing.sentAt && (Date.now() - existing.sentAt) < 60000) {
    const wait = Math.ceil((60000 - (Date.now() - existing.sentAt)) / 1000);
    return res.status(429).json({ error: `Please wait ${wait}s before requesting a new code.` });
  }

  if (db) {
    const user = await db.collection('users').findOne({ phone });
    if (purpose === 'signup' && user) {
      return res.status(409).json({ error: 'An account with this number already exists. Please sign in.' });
    }
    if (purpose === 'login' && !user) {
      return res.status(404).json({ error: 'No account found for this number. Please sign up first.' });
    }
  }

  const otp = generateOTP();
  phoneOtpStore.set(phone, {
    otp, purpose,
    expiresAt: Date.now() + OTP_TTL,
    sentAt: Date.now(),
    attempts: 0,
    verified: false
  });

  try {
    await sendOTPSms(phone, otp);
    res.json({ ok: true, message: `Code sent to ${phone}` });
  } catch (err) {
    console.error('SMS send error:', err.message);
    phoneOtpStore.delete(phone);
    res.status(500).json({ error: 'Failed to send SMS. Please check the number and try again.' });
  }
}

/**
 * POST /api/auth/phone/verify-otp
 * Body: { phone, otp }
 */
async function handlePhoneVerifyOTP(req, res) {
  const { phone: rawPhone, otp } = req.body;
  const phone = normalizePhone(rawPhone);
  if (!phone || !otp) return res.status(400).json({ error: 'Missing phone or code.' });

  const record = phoneOtpStore.get(phone);
  if (!record) return res.status(400).json({ error: 'No code found. Please request a new one.' });
  if (Date.now() > record.expiresAt) {
    phoneOtpStore.delete(phone);
    return res.status(400).json({ error: 'Code expired. Please request a new one.' });
  }
  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    phoneOtpStore.delete(phone);
    return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
  }

  record.attempts++;
  if (record.otp !== String(otp).trim()) {
    const left = MAX_OTP_ATTEMPTS - record.attempts;
    return res.status(400).json({ error: `Incorrect code. ${left} attempt${left === 1 ? '' : 's'} remaining.` });
  }

  record.verified = true;
  res.json({ ok: true, verified: true, purpose: record.purpose });
}

/**
 * POST /api/auth/phone/signup
 * Body: { phone, otp, password, name }
 * Called after OTP verified — creates the account.
 */
async function handlePhoneSignup(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { phone: rawPhone, otp, password, name: rawName } = req.body;
  const phone = normalizePhone(rawPhone);
  const name  = (rawName || '').trim();

  if (!phone || !otp || !password || !name) return res.status(400).json({ error: 'Missing required fields.' });

  const record = phoneOtpStore.get(phone);
  if (!record || !record.verified || record.purpose !== 'signup') {
    return res.status(400).json({ error: 'Phone not verified. Please complete OTP verification first.' });
  }
  if (Date.now() > record.expiresAt) {
    phoneOtpStore.delete(phone);
    return res.status(400).json({ error: 'Verification expired. Please start over.' });
  }

  const pwCheck = validatePassword(password);
  if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.reason });
  if (!name || name.length < 2) return res.status(400).json({ error: 'Please enter your full name.' });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  const exists = await db.collection('users').findOne({ phone });
  if (exists) return res.status(409).json({ error: 'Account already exists. Please sign in.' });

  const userId      = crypto.randomBytes(8).toString('hex');
  const passwordHash = hashPassword(password);
  await db.collection('users').insertOne({
    userId, phone, name, passwordHash,
    createdAt: new Date(), lastLoginAt: new Date()
  });

  phoneOtpStore.delete(phone);

  const token = jwt.sign({ userId, phone, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, userId) || {};
  if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ token, userId, phone, name, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
}

/**
 * POST /api/auth/phone/login
 * Body: { phone, password }
 */
async function handlePhoneLogin(req, res, db, JWT_SECRET, jwt, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { phone: rawPhone, password } = req.body;
  const phone = normalizePhone(rawPhone);
  if (!phone || !password) return res.status(400).json({ error: 'Missing phone or password.' });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });

  const user = await db.collection('users').findOne({ phone });
  if (!user) return res.status(401).json({ error: 'Invalid number or password.' });

  let pwOk = false;
  try { pwOk = verifyPassword(password, user.passwordHash); } catch {}
  if (!pwOk) return res.status(401).json({ error: 'Invalid number or password.' });

  await db.collection('users').updateOne({ phone }, { $set: { lastLoginAt: new Date() } });

  const name  = user.name || '';
  const token = jwt.sign({ userId: user.userId, phone, name, loginTime: Date.now() }, JWT_SECRET, { expiresIn: '30d' });
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, user.userId) || {};
  if (COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ token, userId: user.userId, phone, name, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey });
}

/**
 * POST /api/auth/phone/reset-password
 * Body: { phone, otp, newPassword }
 * Resets password after OTP verification (forgot password flow for phone users).
 */
async function handlePhoneResetPassword(req, res, db) {
  const { phone: rawPhone, otp, newPassword } = req.body;
  const phone = normalizePhone(rawPhone);
  if (!phone || !otp || !newPassword) return res.status(400).json({ error: 'Missing fields.' });

  const record = phoneOtpStore.get(phone);
  if (!record || !record.verified) return res.status(400).json({ error: 'Phone not verified.' });
  if (Date.now() > record.expiresAt) {
    phoneOtpStore.delete(phone);
    return res.status(400).json({ error: 'Code expired. Please start over.' });
  }

  const pwCheck = validatePassword(newPassword);
  if (!pwCheck.ok) return res.status(400).json({ error: pwCheck.reason });

  if (!db) return res.status(503).json({ error: 'Database unavailable.' });
  const user = await db.collection('users').findOne({ phone });
  if (!user) return res.status(404).json({ error: 'Account not found.' });

  const passwordHash = hashPassword(newPassword);
  await db.collection('users').updateOne({ phone }, { $set: { passwordHash, updatedAt: new Date() } });
  phoneOtpStore.delete(phone);
  res.json({ ok: true, message: 'Password updated successfully.' });
}

module.exports = {
  handleSendOTP,
  handleVerifyOTP,
  handleSignup,
  handleLogin,
  handleResetPassword,
  handleLegacyLogin,
  handleMigrateEmail,
  // Phone auth
  handlePhoneSendOTP,
  handlePhoneVerifyOTP,
  handlePhoneSignup,
  handlePhoneLogin,
  handlePhoneResetPassword,
  validateEmailDomain,
  validatePassword,
  ALLOWED_DOMAINS
};
