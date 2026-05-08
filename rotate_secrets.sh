#!/usr/bin/env bash
# rotate_secrets.sh — Helper to rotate secrets for the admin microservice
# WARNING: This script is a helper and does NOT integrate with a KMS. Use a real secrets manager in production.

ENV_FILE=${1:-.env}
BACKUP=${ENV_FILE}.bak.$(date +%s)

if [ ! -f "$ENV_FILE" ]; then
  echo "Env file $ENV_FILE not found. Exiting."
  exit 1
fi

echo "Backing up $ENV_FILE -> $BACKUP"
cp "$ENV_FILE" "$BACKUP"

echo "You can rotate secrets by editing $ENV_FILE. Recommended keys to rotate:
- ADMIN_JWT_SECRET
- ADMIN_JWT_REFRESH_SECRET
- ADMIN_BOOTSTRAP_SECRET
- TOTP_ENCRYPT_KEY
- ADMIN_SIGN_SECRET
"

read -p "Do you want to open $ENV_FILE in nano now? (y/N) " yn
if [[ "$yn" =~ ^[Yy]$ ]]; then
  ${EDITOR:-nano} "$ENV_FILE"
  echo "After editing, restart the service with PM2:"
  echo "  pm2 restart solvemcq-admin"
fi

echo "rotate_secrets.sh finished. For production use a secrets manager (Vault, AWS Secrets Manager, Azure Key Vault)."
