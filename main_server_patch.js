/**
 * ─────────────────────────────────────────────────────────────────
 *  PATCH — add these 3 blocks to your existing backend/server.js
 *  This enables geo-traffic logging for the admin dashboard.
 * ─────────────────────────────────────────────────────────────────
 */

// ── BLOCK 1: Add to the top of server.js alongside other requires ──
const trafficMiddleware = require('./traffic-middleware');   // the file we created

// ── BLOCK 2: Add AFTER your cors() and helmet() middleware, BEFORE routes ──
//    (Search for the line that has app.use(cors(...)) and add the next line after it)

app.use(trafficMiddleware);   // <-- add this line

// ── BLOCK 3: Add to your .env file (main backend .env, not admin .env) ──
/*
  # Admin server internal URL (traffic logging)
  ADMIN_INTERNAL_URL=http://127.0.0.1:3001/admin-api/internal/traffic

  # Shared secret — must match INTERNAL_SECRET in admin-dashboard/backend/.env
  INTERNAL_SECRET=REPLACE_WITH_SAME_32_BYTE_HEX_STRING_AS_ADMIN_ENV
*/

// ─────────────────────────────────────────────────────────────────
//  PUBLIC CONFIG ENDPOINT (optional but recommended)
//  Add this route to server.js so the frontend can read maintenance
//  mode and feature flags from DB instead of static config.js
// ─────────────────────────────────────────────────────────────────

// GET /api/public/config  — no auth required, called on every page load
app.get('/api/public/config', async (req, res) => {
  try {
    const [maintenance, version, features] = await Promise.all([
      db.collection('system_config').findOne({ key: 'maintenance' }),
      db.collection('system_config').findOne({ key: 'version' }),
      db.collection('system_config').findOne({ key: 'feature_flags' }),
    ]);

    res.json({
      maintenance: {
        status:   maintenance?.status   || 'OFF',
        startIST: maintenance?.startIST || '',
        etaIST:   maintenance?.etaIST   || '',
      },
      version: {
        current: version?.current || '8.26',
        prev:    version?.prev    || '8.23',
      },
      features: {
        FEATURE_PHONE_AUTH:     features?.FEATURE_PHONE_AUTH     || 'ON',
        FEATURE_LEGACY_LOGIN:   features?.FEATURE_LEGACY_LOGIN   || 'ON',
        FEATURE_OAUTH_GOOGLE:   features?.FEATURE_OAUTH_GOOGLE   || 'ON',
        FEATURE_OAUTH_GITHUB:   features?.FEATURE_OAUTH_GITHUB   || 'ON',
        FEATURE_OAUTH_APPLE:    features?.FEATURE_OAUTH_APPLE    || 'OFF',
      },
    });
  } catch (e) {
    // Fallback — never let this crash the user-facing app
    res.json({ maintenance: { status: 'OFF' }, version: { current: '8.26' }, features: {} });
  }
});
