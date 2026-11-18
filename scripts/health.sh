#!/bin/bash
# Cluster health over mTLS: the admin client certificate plus basic auth (R-07).
# The password goes to curl through a config on stdin, never on the command line.
set -euo pipefail

if [ ! -f .runtime/.env.secrets ]; then
  echo "No decrypted secret in .runtime/: run make deploy first." >&2
  exit 1
fi

set -a
. config/stack.env
[ -f .env ] && . ./.env
. .runtime/.env.secrets
set +a

# Yellow is the expected ceiling on a single node: replica shards have no second node to
# live on. Red, or no answer within ~90s, is a failure.
health() {
  printf 'user = "admin:%s"\n' "$OPENSEARCH_ADMIN_PASSWORD" | curl -sS -K - \
    --cacert certs/root-ca.pem --cert certs/admin.pem --key certs/admin-key.pem \
    "https://localhost:${OPENSEARCH_PORT}/_cluster/health?pretty&wait_for_status=yellow&timeout=30s"
}
# The REST layer can lag the container start; retry for up to ~90s before failing.
for attempt in $(seq 1 18); do
  if out=$(health 2>&1) && grep -q '"status"' <<<"$out"; then echo "$out"; break; fi
  [ "$attempt" -eq 18 ] && { echo "$out" >&2; exit 1; }
  sleep 5
done

echo "--- same request without a client certificate (must be refused):"
if curl -sS --max-time 5 --cacert certs/root-ca.pem \
     "https://localhost:${OPENSEARCH_PORT}/" -o /dev/null 2>&1; then
  echo "UNEXPECTED: accepted without a client certificate" >&2; exit 1
else
  echo "refused, as required by clientauth_mode: REQUIRE"
fi
