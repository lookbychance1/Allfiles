#!/usr/bin/env bash
# deploy_admin.sh — Deploy ManageMCQ Admin Microservice on Ubuntu 22.04
# Usage: sudo bash deploy_admin.sh /var/www/solvemcq-admin git@github.com:your-org/solvemcq-admin.git

set -euo pipefail
DIR=${1:-/var/www/solvemcq-admin}
REPO=${2:-}
BRANCH=${3:-main}

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "Deploy directory: $DIR"
mkdir -p "$DIR"
chown $SUDO_USER:$SUDO_USER "$DIR"

# Update and install prerequisites
apt update
apt install -y curl wget git build-essential nginx certbot python3-certbot-nginx

# Install Node.js 18.x (NodeSource)
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d. -f1 | tr -d 'v')" -lt 18 ]; then
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
  apt install -y nodejs
fi

# Install PM2 globally
if ! command -v pm2 >/dev/null 2>&1; then
  npm install -g pm2@latest
fi

# Clone or update repo
sudo -u $SUDO_USER bash -c "
if [ -n '$REPO' ]; then
  if [ ! -d '$DIR/.git' ]; then
    git clone --depth 1 --branch $BRANCH '$REPO' '$DIR'
  else
    cd '$DIR' && git fetch --all && git reset --hard origin/$BRANCH
  fi
else
  echo 'No repo provided - ensure admin files are placed in $DIR'
fi
"

# Ensure logs and uploads directories exist
mkdir -p "$DIR/logs" "$DIR/uploads/questions"
chown -R $SUDO_USER:$SUDO_USER "$DIR"

# Install dependencies
cd "$DIR"
sudo -u $SUDO_USER npm install --production

# Create .env from example if not present
if [ -f .env ] ; then
  echo ".env exists - skipping creation"
else
  if [ -f .env.example ]; then
    echo "Creating .env from .env.example - edit values before starting"
    cp .env.example .env
    chown $SUDO_USER:$SUDO_USER .env
  else
    echo "No .env.example found - create .env manually"
  fi
fi

# Start with PM2 using ecosystem file if present
if [ -f pm2_ecosystem_admin.js ]; then
  pm2 start pm2_ecosystem_admin.js --env production || pm2 restart pm2_ecosystem_admin.js --env production
else
  pm2 start admin-server.js --name solvemcq-admin --node-args="--max-old-space-size=512"
fi
pm2 save
pm2 startup systemd -u $SUDO_USER --hp "/home/$SUDO_USER"

# Nginx site config (place-holder) - user must supply domain in next step
NGINX_CONF=/etc/nginx/sites-available/managemcq
if [ ! -f "$NGINX_CONF" ]; then
  cat > "$NGINX_CONF" <<'NGINX'
server {
    listen 80;
    server_name managemcq.sharepremium.in;

    location /.well-known/acme-challenge/ { root /var/www/html; }

    location / {
        proxy_pass http://127.0.0.1:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
NGINX
  ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/managemcq
  nginx -t
  systemctl reload nginx
fi

# Obtain TLS cert with certbot (interactive) - user will be prompted
echo "You should now run: sudo certbot --nginx -d managemcq.sharepremium.in"

echo "Deployment script finished. Edit $DIR/.env with production secrets, then verify PM2 status and obtain TLS cert using certbot."
