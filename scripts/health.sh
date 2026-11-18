#!/bin/bash
# Cluster health over mTLS: the admin client certificate plus basic auth (R-07).
# The password goes to curl through a config on stdin, never on the command line.
set -euo pipefail

set -a
. config/stack.env
[ -f .env ] && . ./.env
. .runtime/.env.secrets
set +a

printf 'user = "admin:%s"\n' "$OPENSEARCH_ADMIN_PASSWORD" | curl -sS --fail -K - \
  --cacert certs/root-ca.pem --cert certs/admin.pem --key certs/admin-key.pem \
  "https://localhost:${OPENSEARCH_PORT}/_cluster/health?pretty"

echo "--- same request without a client certificate (must be refused):"
if curl -sS --max-time 5 --cacert certs/root-ca.pem \
     "https://localhost:${OPENSEARCH_PORT}/" -o /dev/null 2>&1; then
  echo "UNEXPECTED: accepted without a client certificate" >&2; exit 1
else
  echo "refused, as required by clientauth_mode: REQUIRE"
fi
