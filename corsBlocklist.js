/**
 * corsBlocklist.js — Redis-backed CORS abuse detection & IP blocklist
 *
 * How it works:
 *   1. Every CORS violation increments a sliding-window counter for that IP.
 *   2. If an IP hits THRESHOLD violations within WINDOW_SECS, it is blocked for
 *      BLOCK_DURATION_SECS (7 days by default).
 *   3. When a block expires and the IP violates again inside REPEAT_WINDOW_SECS,
 *      it is promoted to a PERMANENT ban (no expiry).
 *   4. Blocked IPs receive 403 before any route handler runs (no wasted processing).
 *
 * Redis key layout:
 *   cors:violations:{ip}   → integer counter     TTL = WINDOW_SECS
 *   cors:blocked:{ip}      → "temp" | "perm"     TTL = BLOCK_DURATION_SECS  (or none for perm)
 *   cors:first_block:{ip}  → ISO timestamp        TTL = REPEAT_WINDOW_SECS
 *
 * Admin management (call from a trusted admin-only route or CLI):
 *   unblockIp(ip)          → removes block & violation counter
 *   isBlocked(ip)          → returns { blocked, type }
 *   listBlocked()          → returns array of { ip, type, ttl }
 */

const { createClient } = require('redis');

// ── Minimal LRU cache (no external deps) ──────────────────────────────────────
// Doubly-linked list + Map → O(1) get/set/delete/evict.
// Stores the last-known block state per IP so blocked IPs stay blocked
// even when Redis is temporarily unreachable.
class LRUCache {
  constructor(maxSize, ttlMs) {
    this.maxSize = maxSize;
    this.ttlMs   = ttlMs;
    this.map     = new Map();
    this.head    = null;  // most recently used
    this.tail    = null;  // least recently used
    this.size    = 0;
  }
  _detach(n) {
    if (n.prev) n.prev.next = n.next; else this.head = n.next;
    if (n.next) n.next.prev = n.prev; else this.tail = n.prev;
    n.prev = n.next = null;
  }
  _prepend(n) {
    n.next = this.head; n.prev = null;
    if (this.head) this.head.prev = n;
    this.head = n;
    if (!this.tail) this.tail = n;
  }
  get(key) {
    const n = this.map.get(key);
    if (!n) return undefined;
    if (Date.now() - n.ts > this.ttlMs) { this._detach(n); this.map.delete(key); this.size--; return undefined; }
    this._detach(n); this._prepend(n);
    return n.value;
  }
  set(key, value) {
    if (this.map.has(key)) {
      const n = this.map.get(key);
      n.value = value; n.ts = Date.now();
      this._detach(n); this._prepend(n); return;
    }
    if (this.size >= this.maxSize) {
      const e = this.tail; this._detach(e); this.map.delete(e.key); this.size--;
    }
    const n = { key, value, ts: Date.now(), prev: null, next: null };
    this._prepend(n); this.map.set(key, n); this.size++;
  }
  delete(key) {
    const n = this.map.get(key);
    if (!n) return;
    this._detach(n); this.map.delete(key); this.size--;
  }
  entries() {
    const now = Date.now(), out = [];
    let n = this.head;
    while (n) { if (now - n.ts <= this.ttlMs) out.push([n.key, n.value]); n = n.next; }
    return out;
  }
}

// LRU config: keep up to 2 000 IPs, evict after 10 min of inactivity.
// Tune LRU_MAX_SIZE up if you serve very high traffic (many distinct IPs/min).
const LRU_MAX_SIZE = 2000;
const LRU_TTL_MS   = 10 * 60 * 1000;  // 10 minutes
const lru = new LRUCache(LRU_MAX_SIZE, LRU_TTL_MS);

// ── Redis client with health tracking ─────────────────────────────────────────
let redisHealthy = false;

const redis = createClient({
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  socket: {
    reconnectStrategy: (attempts) => {
      // Exponential back-off: 200ms, 400ms, 800ms … capped at 10s.
      // The client keeps retrying forever — LRU covers the gap.
      return Math.min(200 * Math.pow(2, attempts), 10_000);
    },
  },
});
redis.on('error',        err => { redisHealthy = false; console.error('[Redis] corsBlocklist error:', err.message); });
redis.on('connect',      ()  => console.log('[Redis] corsBlocklist connected'));
redis.on('ready',        ()  => { redisHealthy = true;  console.log('[Redis] corsBlocklist ready — LRU fallback deactivated'); });
redis.on('reconnecting', ()  => { redisHealthy = false; console.warn('[Redis] corsBlocklist reconnecting — LRU fallback active'); });
redis.on('end',          ()  => { redisHealthy = false; console.warn('[Redis] corsBlocklist connection closed'); });

async function initRedis() {
  if (!redis.isOpen) await redis.connect();
}

// ── Tuneable constants ─────────────────────────────────────────────────────────
const THRESHOLD           = 10;               // violations before auto-block
const WINDOW_SECS         = 5 * 60;           // sliding window: 5 minutes
const BLOCK_DURATION_SECS = 7 * 24 * 3600;    // temp block: 7 days
const REPEAT_WINDOW_SECS  = 30 * 24 * 3600;   // if re-offends within 30 days → perm ban

// ── Key helpers ────────────────────────────────────────────────────────────────
const kViolations  = ip => `cors:violations:${ip}`;
const kBlocked     = ip => `cors:blocked:${ip}`;
const kFirstBlock  = ip => `cors:first_block:${ip}`;

/**
 * Call this on every CORS violation.
 * Increments the counter. If threshold exceeded, auto-blocks the IP.
 * @returns {{ nowBlocked: boolean, type: 'temp'|'perm'|null, count: number }}
 */
async function recordViolation(ip) {
  try {
    // Increment counter; set TTL only on first increment (NX-style via INCR + EXPIRE)
    const count = await redis.incr(kViolations(ip));
    if (count === 1) {
      // First violation in this window — start the clock
      await redis.expire(kViolations(ip), WINDOW_SECS);
    }

    if (count >= THRESHOLD) {
      // Check if already blocked
      const existing = await redis.get(kBlocked(ip));
      if (existing === 'perm') return { nowBlocked: false, type: 'perm', count };
      if (existing === 'temp') return { nowBlocked: false, type: 'temp', count };

      // Decide: temp or permanent?
      const hadPriorBlock = await redis.get(kFirstBlock(ip));
      const blockType = hadPriorBlock ? 'perm' : 'temp';

      if (blockType === 'perm') {
        // Permanent — no TTL
        await redis.set(kBlocked(ip), 'perm');
        await redis.del(kViolations(ip));
        await redis.del(kFirstBlock(ip));
        lru.set(ip, { blocked: true, type: 'perm', source: 'redis' });
        console.warn(`[CORS BLOCKLIST] PERMANENT BAN: ${ip} (re-offended within 30d)`);
      } else {
        // Temp — 7 days
        await redis.set(kBlocked(ip), 'temp', { EX: BLOCK_DURATION_SECS });
        await redis.del(kViolations(ip));
        // Record first-block timestamp so re-offence detection works
        await redis.set(kFirstBlock(ip), new Date().toISOString(), { EX: REPEAT_WINDOW_SECS });
        lru.set(ip, { blocked: true, type: 'temp', source: 'redis' });
        console.warn(`[CORS BLOCKLIST] TEMP BLOCK (7d): ${ip} — reached ${count} violations in window`);
      }

      return { nowBlocked: true, type: blockType, count };
    }

    return { nowBlocked: false, type: null, count };
  } catch (err) {
    console.error('[corsBlocklist] recordViolation error:', err.message);
    return { nowBlocked: false, type: null, count: 0 };
  }
}

/**
 * Check if an IP is currently blocked.
 * Reads from Redis when healthy; falls back to LRU when Redis is unreachable.
 * LRU miss on an unknown IP → fail-open (never block a real user due to Redis outage).
 * @returns {{ blocked: boolean, type: 'temp'|'perm'|null, source: 'redis'|'lru'|'fail-open' }}
 */
async function isBlocked(ip) {
  if (redisHealthy) {
    try {
      const val = await redis.get(kBlocked(ip));
      const result = val
        ? { blocked: true,  type: val,  source: 'redis' }
        : { blocked: false, type: null, source: 'redis' };
      lru.set(ip, result);   // keep LRU warm on every Redis hit
      return result;
    } catch (err) {
      console.error('[corsBlocklist] isBlocked Redis error, trying LRU:', err.message);
      redisHealthy = false;
    }
  }

  // Redis unavailable — consult LRU
  const cached = lru.get(ip);
  if (cached !== undefined) {
    console.warn(`[corsBlocklist] LRU fallback hit for ${ip} (Redis unreachable)`);
    return { ...cached, source: 'lru' };
  }

  // Unknown IP and Redis is down — fail-open to protect real users
  return { blocked: false, type: null, source: 'fail-open' };
}

/**
 * Express middleware — checks if the request IP is blocked before any route runs.
 * Blocked IPs get an immediate 403 with no further processing.
 * Uses LRU fallback automatically when Redis is unreachable.
 */
async function blocklistMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim()
          ?? req.ip
          ?? req.socket?.remoteAddress
          ?? 'unknown';

  const { blocked, type, source } = await isBlocked(ip);
  if (blocked) {
    const reason = type === 'perm'
      ? 'Your IP has been permanently blocked due to repeated abuse.'
      : 'Your IP has been temporarily blocked for 7 days due to CORS abuse.';
    console.warn(`[CORS BLOCKLIST] Blocked request from ${ip} (${type}, via ${source}): ${req.method} ${req.path}`);
    return res.status(403).json({ error: 'Access denied.', reason });
  }
  next();
}

/**
 * Admin: manually unblock an IP (removes block + violation counter + first-block marker).
 * Call this from your admin route or a one-off CLI script.
 */
async function unblockIp(ip) {
  lru.delete(ip);   // always clear LRU regardless of Redis state
  try {
    await redis.del(kBlocked(ip));
    await redis.del(kViolations(ip));
    await redis.del(kFirstBlock(ip));
    console.log(`[CORS BLOCKLIST] Manually unblocked: ${ip}`);
    return { ok: true };
  } catch (err) {
    console.error('[corsBlocklist] unblockIp error:', err.message);
    return { ok: false, error: err.message };
  }
}

/**
 * Admin: list all currently blocked IPs with their type and remaining TTL.
 * @returns {Promise<Array<{ ip: string, type: string, ttlSeconds: number|'permanent' }>>}
 */
async function listBlocked() {
  try {
    const keys = await redis.keys('cors:blocked:*');
    const results = await Promise.all(keys.map(async key => {
      const ip   = key.replace('cors:blocked:', '');
      const type = await redis.get(key);
      const ttl  = await redis.ttl(key);  // -1 = no expiry (perm), -2 = gone
      return {
        ip,
        type: type || 'unknown',
        ttlSeconds: ttl === -1 ? 'permanent' : ttl,
      };
    }));
    return results.sort((a, b) => {
      if (a.type === 'perm' && b.type !== 'perm') return -1;
      if (b.type === 'perm' && a.type !== 'perm') return 1;
      return 0;
    });
  } catch (err) {
    console.error('[corsBlocklist] listBlocked error:', err.message);
    return [];
  }
}

/**
 * Admin: manually add a permanent ban (for known bad IPs you want to block immediately).
 */
async function permanentBan(ip, reason = 'manual') {
  lru.set(ip, { blocked: true, type: 'perm', source: 'redis' });  // takes effect in memory immediately
  try {
    await redis.set(kBlocked(ip), 'perm');
    await redis.del(kViolations(ip));
    console.warn(`[CORS BLOCKLIST] Manual permanent ban: ${ip} (reason: ${reason})`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Admin: returns LRU and Redis health stats — useful for the /api/admin/blocklist endpoint.
 */
function lruStats() {
  return {
    redisHealthy,
    lruSize:    lru.size,
    lruMaxSize: LRU_MAX_SIZE,
    lruTtlMs:   LRU_TTL_MS,
  };
}

module.exports = {
  initRedis,
  recordViolation,
  isBlocked,
  blocklistMiddleware,
  unblockIp,
  listBlocked,
  permanentBan,
  lruStats,
};
