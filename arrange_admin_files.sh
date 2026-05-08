#!/usr/bin/env bash
# arrange_admin_files.sh
# Usage: 
# 1) Download the generated admin files and .env.example, package.json, deploy_admin.sh, pm2_ecosystem_admin.js, admin-dashboard.html and all route files into the same directory as this script.
# 2) Run: bash arrange_admin_files.sh
# This script creates the recommended folder tree and moves files into their places.

set -euo pipefail
ROOT_DIR=${1:-./manage-mcq-admin}
USER=$(whoami)

FILES_ROOT=$(pwd)

echo "Creating folder structure under: $ROOT_DIR"
mkdir -p "$ROOT_DIR"
mkdir -p "$ROOT_DIR/routes" "$ROOT_DIR/models" "$ROOT_DIR/admin-public" "$ROOT_DIR/logs" "$ROOT_DIR/uploads/questions" "$ROOT_DIR/scripts" "$ROOT_DIR/utils"

# Helper to move if exists
mv_if_exists () {
  local src="$1"
  local dst="$2"
  if [ -f "$FILES_ROOT/$src" ]; then
    echo "Moving $src -> $dst"
    mv "$FILES_ROOT/$src" "$ROOT_DIR/$dst"
  else
    echo "Warning: $src not found in current directory — expected to be downloaded. Skipping."
  fi
}

# Top-level files
mv_if_exists "admin-server.js" "admin-server.js"
mv_if_exists "package.json" "package.json"
mv_if_exists ".env.example" ".env.example"
mv_if_exists "pm2_ecosystem_admin.js" "pm2_ecosystem_admin.js"
mv_if_exists "deploy_admin.sh" "deploy_admin.sh"

# Static admin UI
mv_if_exists "admin-dashboard.html" "admin-public/admin-dashboard.html"

# Route files (place under routes/)
mv_if_exists "adminAuth.js" "routes/adminAuth.js"
mv_if_exists "adminMiddleware.js" "routes/adminMiddleware.js"
mv_if_exists "devtoolDetect.js" "routes/devtoolDetect.js"
mv_if_exists "geoStats.js" "routes/geoStats.js"
mv_if_exists "userManagement.js" "routes/userManagement.js"
mv_if_exists "questionManagement.js" "routes/questionManagement.js"
mv_if_exists "notificationManager.js" "routes/notificationManager.js"
mv_if_exists "systemMaintenance.js" "routes/systemMaintenance.js"
mv_if_exists "versionUpdate.js" "routes/versionUpdate.js"
mv_if_exists "adminBlocklist.js" "routes/adminBlocklist.js"

# Optional utilities
mv_if_exists "deploy_admin.sh" "deploy_admin.sh"

# Make sure logs and upload dirs exist
mkdir -p "$ROOT_DIR/logs" "$ROOT_DIR/uploads/questions"
chmod 755 "$ROOT_DIR" || true
chmod 755 "$ROOT_DIR/logs" || true
chmod 755 "$ROOT_DIR/uploads/questions" || true

# Set ownership to current user (not root) to allow edits
chown -R "$USER":"$USER" "$ROOT_DIR" || true

cat <<'EOF'

Done. Next steps (run from this machine or the server where you will deploy):

1) Review .env.example: edit $ROOT_DIR/.env.example and fill production values. Save as .env.

2) Install dependencies and start (on server):
   cd /path/to/manage-mcq-admin
   npm ci
   # then start using pm2 ecosystem file
   pm2 start pm2_ecosystem_admin.js --env production
   pm2 save

3) Please ensure MongoDB and Redis connection strings point to the separate instances you prefer.

4) Configure Nginx (or the provided deploy_admin.sh) to reverse-proxy managemcq.sharepremium.in to http://127.0.0.1:4000 and obtain TLS cert with certbot.

5) Create the initial admin (bootstrap):
   curl -X POST https://managemcq.sharepremium.in/api/admin/auth/create-admin \
     -H 'Content-Type: application/json' \
     -d '{"bootstrapSecret":"<ADMIN_BOOTSTRAP_SECRET>","username":"your-admin","password":"VeryStrongPassword123!","role":"superadmin"}'

6) Verify logs and PM2 status:
   tail -f logs/admin-access.log
   pm2 status

If anything is missing (file warnings printed above), download those generated files from this chat and re-run the script.

EOF

echo "arrange_admin_files.sh finished. Check the warnings above for any missing files."
