# ─────────────────────────────────────────────────────────────────
#  SolveMCQ Admin Server — Environment Variables
#  File: /path/to/admin-dashboard/backend/.env
#  NEVER commit this file. Add it to .gitignore immediately.
# ─────────────────────────────────────────────────────────────────

# Port this admin server listens on (Nginx proxies here)
ADMIN_PORT=3001

# Your existing MongoDB connection string (same DB, new collections)
MONGO_URI=mongodb://localhost:27017/MCQwebData

# Redis (used for brute-force counters + session suspension flags)
REDIS_URL=redis://127.0.0.1:6379

# ── JWT Secrets — generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
ADMIN_JWT_SECRET=REPLACE_WITH_64_BYTE_HEX_STRING_1
ADMIN_REFRESH_SECRET=REPLACE_WITH_64_BYTE_HEX_STRING_2

# ── Admin panel origin (exact URL, no trailing slash)
ADMIN_ORIGIN=https://managemcq.sharepremium.in

# ── Optional: comma-separated list of IPs allowed to access the panel
#    Leave blank to allow all IPs (rely on login + TOTP instead)
ADMIN_IP_ALLOWLIST=

# ── Shared internal secret between admin-server and main server
#    Used only for the /admin-api/internal/traffic endpoint
#    Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
INTERNAL_SECRET=REPLACE_WITH_32_BYTE_HEX_STRING

# ── Path to the CORS violations log written by your main backend
#    Adjust to wherever cors-violations.log actually lives
CORS_LOG_PATH=/var/www/solvemcq/backend/cors-violations.log
