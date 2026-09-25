#!/bin/bash
# Script to configure HashiCorp Vault dev server for Admin Backend KMS
# Usage:
#   ./setup-vault.sh [ROOT_TOKEN]
# Example:
#   ./setup-vault.sh hvs.EOtAez9UwGwqquffKwx82h50

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ENV_FILE="$DIR/.env"

if [ -f "$ENV_FILE" ]; then
  # Load role_id and secret_id from .env if available
  VAULT_ROLE_ID=$(grep '^VAULT_ROLE_ID=' "$ENV_FILE" | cut -d '=' -f2 | tr -d '"\r ')
  VAULT_SECRET_ID=$(grep '^VAULT_SECRET_ID=' "$ENV_FILE" | cut -d '=' -f2 | tr -d '"\r ')
  ENV_VAULT_ADDR=$(grep '^VAULT_ADDR=' "$ENV_FILE" | cut -d '=' -f2 | tr -d '"\r ')
fi

export VAULT_ADDR="${ENV_VAULT_ADDR:-http://127.0.0.1:8200}"

# Token from parameter, environment, or prompt
if [ -n "$1" ]; then
  export VAULT_TOKEN="$1"
elif [ -z "$VAULT_TOKEN" ]; then
  echo "Error: Vault root token is required."
  echo "Usage: ./setup-vault.sh <VAULT_ROOT_TOKEN>"
  exit 1
fi

ROLE_ID="${VAULT_ROLE_ID:-d5acf7da-8685-3742-b82c-84cfed83206c}"
SECRET_ID="${VAULT_SECRET_ID:-b41deb5a-5310-4f15-0e81-a894baf31092}"

echo "Configuring Vault at $VAULT_ADDR ..."

# 1. Enable transit engine if not already enabled
if ! vault secrets list | grep -q "^transit/"; then
  echo "Enabling transit engine..."
  vault secrets enable transit
else
  echo "Transit engine already enabled."
fi

# 2. Create transit key if not exists
echo "Ensuring transit key 'tenant-master-key' exists..."
vault write -f transit/keys/tenant-master-key >/dev/null 2>&1 || true

# 3. Enable AppRole auth if not enabled
if ! vault auth list | grep -q "^approle/"; then
  echo "Enabling approle auth..."
  vault auth enable approle
else
  echo "AppRole auth already enabled."
fi

# 4. Upload backend policy
echo "Writing backend-policy..."
vault policy write backend-policy - <<EOF
path "transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# 5. Configure AppRole
echo "Configuring admin-backend AppRole..."
vault write auth/approle/role/admin-backend \
  token_policies="backend-policy" \
  token_ttl=24h \
  token_max_ttl=72h >/dev/null

# 6. Set custom role-id and secret-id matching .env
vault write auth/approle/role/admin-backend/role-id role_id="$ROLE_ID" >/dev/null
vault write auth/approle/role/admin-backend/custom-secret-id secret_id="$SECRET_ID" >/dev/null 2>&1 || true

echo "Vault successfully configured for Admin Backend AppRole!"
echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"
