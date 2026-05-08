#!/usr/bin/env bash
# bootstrap_create_admin.sh — Create first superadmin via admin API
# Usage:
#   ./bootstrap_create_admin.sh <ADMIN_URL> <BOOTSTRAP_SECRET> <USERNAME> <PASSWORD> [role]
# Example:
#   ./bootstrap_create_admin.sh https://managemcq.sharepremium.in my_bootstrap_secret admin 'VeryStrongPassword!' superadmin

set -euo pipefail
if [ "$#" -lt 4 ]; then
  echo "Usage: $0 <ADMIN_URL> <BOOTSTRAP_SECRET> <USERNAME> <PASSWORD> [role]"
  exit 1
fi

ADMIN_URL="$1"
BOOTSTRAP_SECRET="$2"
USERNAME="$3"
PASSWORD="$4"
ROLE=${5:-superadmin}

PAYLOAD=$(jq -n --arg bs "$BOOTSTRAP_SECRET" --arg u "$USERNAME" --arg p "$PASSWORD" --arg r "$ROLE" '{bootstrapSecret: $bs, username: $u, password: $p, role: $r}')

echo "Creating admin '$USERNAME' with role '$ROLE' on $ADMIN_URL"

HTTP_CODE=$(curl -s -o /tmp/bootstrap_resp.txt -w "%{http_code}" -X POST "$ADMIN_URL/api/admin/auth/create-admin" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  echo "Success: admin created. Server response:"; cat /tmp/bootstrap_resp.txt
  exit 0
else
  echo "Failed (HTTP $HTTP_CODE). Response:"; cat /tmp/bootstrap_resp.txt
  exit 2
fi
