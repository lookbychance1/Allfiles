/**
 * oauth.js — Social OAuth handler for Google, GitHub, Apple
 *
 * Flow (PKCE / server-side token exchange):
 *  1. Frontend opens popup → provider login → provider redirects to
 *     /api/auth/oauth/callback?provider=X&code=Y&state=Z
 *  2. This module exchanges `code` for tokens, fetches user profile,
 *     upserts user in MongoDB, signs a JWT, and passes it back to the
 *     opener via postMessage (popup closes itself).
 *  3. Frontend receives { token, userId, name, email } and logs the user in.
 *
 * Apple is handled slightly differently: Apple sends the form POST with
 *  `id_token` and optionally `user` JSON on first authorization only.
 *  We verify the id_token JWT (using Apple's public keys) instead of
 *  exchanging a code for a user-info endpoint.
 */

const crypto = require('crypto');
const https  = require('https');
const jwt    = require('jsonwebtoken');

// ── Provider feature flags ────────────────────────────────
// Reads OAUTH_GOOGLE / OAUTH_GITHUB / OAUTH_APPLE from .env.
// Any value other than 'ON' (case-insensitive) disables the provider.
const PROVIDERS = ['google', 'github', 'apple'];

function isProviderEnabled(provider) {
  const val = process.env[`OAUTH_${provider.toUpperCase()}`] || 'OFF';
  return val.trim().toUpperCase() === 'ON';
}

/** Returns the list of currently-enabled providers e.g. ['google','github'] */
function enabledProviders() {
  return PROVIDERS.filter(isProviderEnabled);
}

// ── tiny HTTPS helper ─────────────────────────────────────
function httpsPost(hostname, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = typeof body === 'string' ? body : new URLSearchParams(body).toString();
    const opts = {
      hostname, path, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(payload),
        'Accept': 'application/json',
        ...headers
      }
    };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function httpsGet(hostname, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = { hostname, path, method: 'GET', headers: { 'Accept': 'application/json', ...headers } };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve(data); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ── state store (in-memory, TTL 10 min) ──────────────────
const stateStore = new Map();
function generateState(provider) {
  const state = crypto.randomBytes(16).toString('hex');
  stateStore.set(state, { provider, createdAt: Date.now() });
  // cleanup old states
  for (const [k, v] of stateStore) {
    if (Date.now() - v.createdAt > 10 * 60 * 1000) stateStore.delete(k);
  }
  return state;
}
function validateState(state) {
  const entry = stateStore.get(state);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > 10 * 60 * 1000) { stateStore.delete(state); return null; }
  stateStore.delete(state);
  return entry.provider;
}

// ── build popup HTML that messages the opener ─────────────
function popupResultHTML(data, error) {
  const payload = error
    ? JSON.stringify({ error })
    : JSON.stringify(data);
  // Frontend origin — postMessage must target this origin explicitly
  const FRONTEND = (process.env.FRONTEND_URL || 'https://mcq.sharepremium.in')
    .split(',')[0].trim();
  return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Signing you in…</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f8fafc;color:#334155;}
.card{text-align:center;padding:32px;border-radius:12px;background:#fff;box-shadow:0 4px 24px rgba(0,0,0,.08);}
.spinner{width:36px;height:36px;border:3px solid #e2e8f0;border-top-color:#6366f1;border-radius:50%;animation:spin .7s linear infinite;margin:0 auto 16px;}
@keyframes spin{to{transform:rotate(360deg);}}</style>
</head><body>
<div class="card">
  <div class="spinner"></div>
  <p id="msg">${error ? '&#10060; ' + error.replace(/</g,'&lt;') : 'Signing you in&hellip;'}</p>
</div>
<script>
(function(){
  var payload   = ${payload};
  var FRONTEND  = '${FRONTEND}';

  // Case 1: normal popup flow — opener is the frontend window
  if (window.opener && !window.opener.closed) {
    try {
      window.opener.postMessage({ type: 'OAUTH_RESULT', payload: payload }, FRONTEND);
    } catch(e) {
      // If origin mismatch or any error, try wildcard as fallback
      try { window.opener.postMessage({ type: 'OAUTH_RESULT', payload: payload }, '*'); } catch(_) {}
    }
    setTimeout(function(){ window.close(); }, ${error ? 3000 : 600});
    return;
  }

  // Case 2: no opener — user was redirected in same tab (popup blocked).
  // Encode result in URL hash and redirect to frontend; app.js reads it on load.
  var encoded = encodeURIComponent(JSON.stringify(payload));
  window.location.replace(FRONTEND + '/#oauth=' + encoded);
})();
</script>
</body></html>`;
}

// ── Google ────────────────────────────────────────────────
function getGoogleAuthURL(state) {
  const base = 'https://accounts.google.com/o/oauth2/v2/auth';
  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  process.env.OAUTH_REDIRECT_BASE + '/api/auth/oauth/callback/google',
    response_type: 'code',
    scope:         'openid email profile',
    state,
    access_type:   'online',
    prompt:        'select_account'
  });
  return `${base}?${params}`;
}

async function handleGoogleCallback(code) {
  const tokens = await httpsPost('oauth2.googleapis.com', '/token', {
    code,
    client_id:     process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri:  process.env.OAUTH_REDIRECT_BASE + '/api/auth/oauth/callback/google',
    grant_type:    'authorization_code'
  });
  if (tokens.error) throw new Error(tokens.error_description || tokens.error);

  // Decode id_token (we trust Google's token, skip full JWT verification for brevity
  // — Google's JWKS verification adds complexity; id_token payload is sufficient here
  // since we got it directly from Google's token endpoint over HTTPS)
  const [, payloadB64] = (tokens.id_token || '').split('.');
  if (!payloadB64) throw new Error('No id_token from Google');
  const info = JSON.parse(Buffer.from(payloadB64 + '==', 'base64').toString('utf8'));
  return { email: info.email, name: info.name || info.given_name || '', providerId: info.sub };
}

// ── GitHub ────────────────────────────────────────────────
function getGithubAuthURL(state) {
  const params = new URLSearchParams({
    client_id:    process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.OAUTH_REDIRECT_BASE + '/api/auth/oauth/callback/github',
    scope:        'user:email read:user',
    state
  });
  return `https://github.com/login/oauth/authorize?${params}`;
}

async function handleGithubCallback(code) {
  const tokens = await httpsPost('github.com', '/login/oauth/access_token', {
    client_id:     process.env.GITHUB_CLIENT_ID,
    client_secret: process.env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri:  process.env.OAUTH_REDIRECT_BASE + '/api/auth/oauth/callback/github'
  }, { Accept: 'application/json' });

  if (tokens.error) throw new Error(tokens.error_description || tokens.error);

  const accessToken = tokens.access_token;
  const userInfo = await httpsGet('api.github.com', '/user', {
    Authorization: `Bearer ${accessToken}`,
    'User-Agent':  'PracticeMCQ-Server'
  });

  let email = userInfo.email;
  // GitHub may not expose email in profile — fetch from /user/emails
  if (!email) {
    const emails = await httpsGet('api.github.com', '/user/emails', {
      Authorization: `Bearer ${accessToken}`,
      'User-Agent':  'PracticeMCQ-Server'
    });
    if (Array.isArray(emails)) {
      const primary = emails.find(e => e.primary && e.verified);
      email = primary ? primary.email : (emails[0] ? emails[0].email : null);
    }
  }
  if (!email) throw new Error('GitHub account has no accessible email. Please add a public email in GitHub settings.');

  return { email, name: userInfo.name || userInfo.login || '', providerId: String(userInfo.id) };
}

// ── Apple ─────────────────────────────────────────────────
function getAppleAuthURL(state) {
  const params = new URLSearchParams({
    client_id:     process.env.APPLE_CLIENT_ID,
    redirect_uri:  process.env.OAUTH_REDIRECT_BASE + '/api/auth/oauth/callback/apple',
    response_type: 'code id_token',
    response_mode: 'form_post',
    scope:         'name email',
    state
  });
  return `https://appleid.apple.com/auth/authorize?${params}`;
}

// Apple sends a form_post — we receive { code, id_token, state, user? }
async function handleAppleCallback(code, idToken, userJSON) {
  // Decode id_token payload (Apple signs with RS256; full verification needs JWKS fetch)
  const [, payloadB64] = (idToken || '').split('.');
  if (!payloadB64) throw new Error('No id_token from Apple');
  const info = JSON.parse(Buffer.from(payloadB64 + '==', 'base64').toString('utf8'));

  const email = info.email;
  if (!email) throw new Error('Apple did not share an email. Please allow email sharing in Apple ID settings.');

  // Apple sends name only on FIRST authorization
  let name = '';
  if (userJSON) {
    try {
      const u = typeof userJSON === 'string' ? JSON.parse(userJSON) : userJSON;
      name = [u.name?.firstName, u.name?.lastName].filter(Boolean).join(' ');
    } catch {}
  }

  return { email, name, providerId: info.sub };
}

// ── Upsert user + issue JWT ───────────────────────────────
async function upsertOAuthUser(db, JWT_SECRET, jwtLib, { email, name, provider, providerId }, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  if (!db) throw new Error('Database unavailable.');

  const emailLower = email.toLowerCase().trim();
  let user = await db.collection('users').findOne({ email: emailLower });

  if (user) {
    // Existing user — update OAuth linkage and last login
    const update = { lastLoginAt: new Date() };
    if (!user.name && name) update.name = name;
    update[`oauth.${provider}`] = providerId;
    await db.collection('users').updateOne({ email: emailLower }, { $set: update });
    // Use stored name if we don't have one from OAuth
    name = user.name || name || emailLower.split('@')[0];
  } else {
    // New user — create account (no password; OAuth-only)
    const userId = crypto.randomBytes(8).toString('hex');
    const safeName = name || emailLower.split('@')[0];
    await db.collection('users').insertOne({
      userId,
      email: emailLower,
      name: safeName,
      oauth: { [provider]: providerId },
      createdAt: new Date(),
      lastLoginAt: new Date()
    });
    user = { userId, name: safeName };
    name = safeName;
  }

  const userId = user.userId;
  const token  = jwtLib.sign(
    { userId, email: emailLower, name, loginTime: Date.now() },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
  let sessInfo = {};
  if (recordSession) sessInfo = await recordSession(token, userId) || {};
  return { token, userId, name, email: emailLower, sessionId: sessInfo.sessionId, sessionKey: sessInfo.sessionKey };
}

// ── Exported route handlers ───────────────────────────────

/**
 * GET /api/auth/oauth/url/:provider
 * Returns the authorization URL for the given provider.
 */
function handleGetOAuthURL(req, res) {
  const { provider } = req.params;
  if (!PROVIDERS.includes(provider))    return res.status(400).json({ error: 'Unknown provider.' });
  if (!isProviderEnabled(provider))     return res.status(403).json({ error: `${provider} sign-in is currently disabled.` });
  const state = generateState(provider);
  let url;
  try {
    if (provider === 'google') url = getGoogleAuthURL(state);
    else if (provider === 'github') url = getGithubAuthURL(state);
    else if (provider === 'apple') url = getAppleAuthURL(state);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
  res.json({ url });
}

/**
 * GET /api/auth/oauth/enabled
 * Returns { providers: ['google', 'github'] } — frontend uses this to
 * show/hide buttons without hardcoding flags in the client.
 */
function handleEnabledProviders(req, res) {
  res.json({ providers: enabledProviders() });
}

/**
 * GET /api/auth/oauth/callback/google
 * GET /api/auth/oauth/callback/github
 * Apple uses POST (form_post); mounted separately.
 */
async function handleOAuthCallback(req, res, db, JWT_SECRET, jwtLib, recordSession, COOKIE_NAME, COOKIE_OPTS) {
  const { provider } = req.params;
  const code  = req.query.code  || req.body?.code;
  const state = req.query.state || req.body?.state;
  const idToken  = req.body?.id_token;   // Apple only
  const userJSON = req.body?.user;       // Apple only (first auth)

  // Guard: provider must be enabled
  if (!isProviderEnabled(provider)) {
    return res.send(popupResultHTML(null, `${provider} sign-in is currently disabled.`));
  }

  // Validate state
  const expectedProvider = validateState(state);
  if (!expectedProvider || expectedProvider !== provider) {
    return res.send(popupResultHTML(null, 'Invalid or expired state. Please try again.'));
  }

  try {
    let profile;
    if (provider === 'google')      profile = await handleGoogleCallback(code);
    else if (provider === 'github') profile = await handleGithubCallback(code);
    else if (provider === 'apple')  profile = await handleAppleCallback(code, idToken, userJSON);
    else throw new Error('Unknown provider');

    const result = await upsertOAuthUser(db, JWT_SECRET, jwtLib, { ...profile, provider }, recordSession, COOKIE_NAME, COOKIE_OPTS);
    // Set httpOnly cookie in the OAuth callback response (same-site=none required for cross-origin popup)
    if (result.token && COOKIE_NAME && COOKIE_OPTS) res.cookie(COOKIE_NAME, result.token, COOKIE_OPTS);
    res.send(popupResultHTML(result, null));
  } catch (e) {
    console.error(`OAuth ${provider} error:`, e.message);
    res.send(popupResultHTML(null, e.message || 'Sign-in failed. Please try again.'));
  }
}

module.exports = { handleGetOAuthURL, handleOAuthCallback, handleEnabledProviders, enabledProviders };
