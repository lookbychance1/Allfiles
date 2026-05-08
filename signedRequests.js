/**
 * signedRequests.js — Redis-backed version
 * Replaces in-memory keyStore and nonceStore with Redis so all
 * PM2 cluster workers share the same signing state.
 *
 * Redis key layout:
 *   sr:key:{sessionId}   → JSON { current, previous, reqCount }   TTL = KEY_TTL_MS
 *   sr:nonce:{sessionId}:{nonce} → "1"                            TTL = NONCE_TTL_MS
 */

'use strict';

const crypto = require('crypto');
const { createClient } = require('redis');

// ── Tunables ─────────────────────────────────────────────────────────────────
const ROTATE_AFTER_N   = 50;
const ROTATE_AFTER_MS  = 45 * 1000;
const GRACE_MS         = 5000;
const TS_WINDOW_MS     = 15000;
const NONCE_TTL_MS     = 30000;
const KEY_TTL_MS       = 65 * 60 * 1000;   // 65 minutes

// ── Redis client ──────────────────────────────────────────────────────────────
const redis = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  socket: { reconnectStrategy: retries => Math.min(retries * 100, 3000) }
});

redis.on('error', err => console.error('[Redis] signedRequests error:', err.message));
redis.on('connect', () => console.log('[Redis] signedRequests connected'));

// Connect immediately — server.js awaits initRedis() before listen()
async function initRedis() {
  if (!redis.isOpen) await redis.connect();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function makeKey() {
  return crypto.randomBytes(32).toString('hex');
}

function keyName(sessionId)   { return `sr:key:${sessionId}`; }
function nonceName(sid, n)    { return `sr:nonce:${sid}:${n}`; }

function encryptNextKey(nextKey, currentKey) {
  try {
    const keyBuf = Buffer.from(currentKey, 'hex');
    const iv     = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
    const enc    = Buffer.concat([cipher.update(nextKey, 'hex'), cipher.final()]);
    const tag    = cipher.getAuthTag();
    return iv.toString('hex') + tag.toString('hex') + enc.toString('hex');
  } catch { return null; }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Create a fresh signing key for a session.
 * Called on login / validate.
 * Returns the key string (sent to browser).
 */
async function createSessionKey(sessionId) {
  const key   = makeKey();
  const entry = { current: { key, issuedAt: Date.now() }, previous: null, reqCount: 0 };
  await redis.set(keyName(sessionId), JSON.stringify(entry), { PX: KEY_TTL_MS });
  return key;
}

/**
 * Delete a session's signing key (on logout).
 */
async function deleteSessionKey(sessionId) {
  await redis.del(keyName(sessionId));
}

// ── HMAC (mirrors frontend) ───────────────────────────────────────────────────
function computeHMAC(key, method, path, bodyStr, ts, nonce) {
  const msg = [method.toUpperCase(), path, bodyStr || '', ts, nonce].join('\n');
  return crypto.createHmac('sha256', Buffer.from(key, 'hex')).update(msg).digest('hex');
}

// ── Express middleware ────────────────────────────────────────────────────────
function makeSignedAuthMiddleware(jwt, JWT_SECRET, cookieName) {
  return async function signedAuth(req, res, next) {

    // 1. JWT ──────────────────────────────────────────────────────────────────
    const token = req.cookies?.[cookieName] || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    let payload;
    try {
      payload = jwt.verify(token, JWT_SECRET);
      if (!payload.userId) throw new Error('no userId');
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // 2. Signed-request headers ───────────────────────────────────────────────
    const sessionId = req.headers['x-session-id'];
    const ts        = req.headers['x-ts'];
    const nonce     = req.headers['x-nonce'];
    const sign      = req.headers['x-sign'];

    if (!sessionId || !ts || !nonce || !sign) {
      return res.status(401).json({ error: 'Missing request signature headers' });
    }

    // Timestamp freshness
    const tsNum = parseInt(ts, 10);
    if (isNaN(tsNum) || Math.abs(Date.now() - tsNum) > TS_WINDOW_MS) {
      return res.status(401).json({ error: 'Request timestamp expired' });
    }

    // 3. Load key entry from Redis ─────────────────────────────────────────────
    let entry;
    try {
      const raw = await redis.get(keyName(sessionId));
      if (!raw) return res.status(401).json({ error: 'Session key not found. Please refresh.', code: 'KEY_MISSING' });
      entry = JSON.parse(raw);
    } catch {
      return res.status(401).json({ error: 'Session key not found. Please refresh.', code: 'KEY_MISSING' });
    }

    // 4. Verify HMAC ──────────────────────────────────────────────────────────
    const bodyStr = req.body && Object.keys(req.body).length > 0
      ? JSON.stringify(req.body)
      : '';

    let keyUsed       = null;
    let usingPrevious = false;

    const expectedCurrent = computeHMAC(entry.current.key, req.method, req.path, bodyStr, ts, nonce);
    if (sign.length === expectedCurrent.length &&
        crypto.timingSafeEqual(Buffer.from(sign, 'hex'), Buffer.from(expectedCurrent, 'hex'))) {
      keyUsed = entry.current.key;
    } else if (
      entry.previous &&
      Date.now() - entry.previous.rotatedAt < GRACE_MS
    ) {
      const expectedPrev = computeHMAC(entry.previous.key, req.method, req.path, bodyStr, ts, nonce);
      if (sign.length === expectedPrev.length &&
          crypto.timingSafeEqual(Buffer.from(sign, 'hex'), Buffer.from(expectedPrev, 'hex'))) {
        keyUsed       = entry.previous.key;
        usingPrevious = true;
      }
    }

    if (!keyUsed) return res.status(401).json({ error: 'Invalid request signature' });

    // 5. Nonce (replay) check ─────────────────────────────────────────────────
    const nk = nonceName(sessionId, nonce);
    try {
      const set = await redis.set(nk, '1', { NX: true, PX: NONCE_TTL_MS });
      if (!set) return res.status(401).json({ error: 'Duplicate request (replay detected)' });
    } catch {
      return res.status(401).json({ error: 'Duplicate request (replay detected)' });
    }

    // 6. Key rotation ─────────────────────────────────────────────────────────
    entry.reqCount++;
    const ageMs        = Date.now() - entry.current.issuedAt;
    const needsRotation = entry.reqCount >= ROTATE_AFTER_N || ageMs >= ROTATE_AFTER_MS;

    if (needsRotation) {
      const oldKey = entry.current.key;
      const newKey = makeKey();
      entry.previous = { key: oldKey, issuedAt: entry.current.issuedAt, rotatedAt: Date.now() };
      entry.current  = { key: newKey, issuedAt: Date.now() };
      entry.reqCount = 0;

      const encrypted = encryptNextKey(newKey, oldKey);
      if (encrypted) {
        res.setHeader('x-next-key', encrypted);
        res.setHeader('x-key-rotated', '1');
      }
    }

    // Save updated entry back to Redis (reset TTL on activity)
    await redis.set(keyName(sessionId), JSON.stringify(entry), { PX: KEY_TTL_MS });

    // 7. Attach user ──────────────────────────────────────────────────────────
    req.user      = payload;
    req.sessionId = sessionId;
    next();
  };
}

module.exports = {
  initRedis,
  createSessionKey,
  deleteSessionKey,
  encryptNextKey,
  computeHMAC,
  makeSignedAuthMiddleware,
  ROTATE_AFTER_N,
  ROTATE_AFTER_MS,
};
