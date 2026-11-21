#!/bin/bash
# Prove the availability alert end to end (R-18): stop OpenSearch, wait until Alertmanager
# reports SocServiceDown firing, start OpenSearch again, wait until the alert resolves.
# Alertmanager is queried over TLS, verified against the project root CA.
set -euo pipefail

# shellcheck source=/dev/null
. config/stack.env
AM="https://localhost:${ALERTMANAGER_PORT}/api/v2/alerts?filter=alertname%3D%22SocServiceDown%22"
COMPOSE=(docker compose --env-file config/stack.env)
[ -f .runtime/.env.secrets ] && COMPOSE+=(--env-file .runtime/.env.secrets)

firing() { curl -sS --cacert certs/root-ca.pem "$AM" | jq -r '.[] | select(.status.state=="active") | .labels.instance'; }
stamp() { date -u +%H:%M:%SZ; }

echo "$(stamp) firing before the test: $(firing | wc -l | tr -d ' ')"
echo "$(stamp) stopping opensearch"
"${COMPOSE[@]}" stop opensearch >/dev/null

for _ in $(seq 1 36); do
  hits=$(firing)
  if [ -n "$hits" ]; then
    echo "$(stamp) ALERT SocServiceDown firing for: $(echo "$hits" | tr '\n' ' ')"
    curl -sS --cacert certs/root-ca.pem "$AM" \
      | jq -r '.[] | "  severity=\(.labels.severity) risk=\(.labels.risk) startsAt=\(.startsAt)\n  summary: \(.annotations.summary)"'
    break
  fi
  sleep 5
done
[ -n "${hits:-}" ] || { echo "$(stamp) alert did not fire within 3 minutes" >&2; "${COMPOSE[@]}" start opensearch; exit 1; }

echo "$(stamp) starting opensearch again"
"${COMPOSE[@]}" start opensearch >/dev/null
for _ in $(seq 1 48); do
  [ -z "$(firing)" ] && { echo "$(stamp) alert resolved: OpenSearch reachable over mTLS again"; exit 0; }
  sleep 5
done
echo "$(stamp) alert still firing after 4 minutes" >&2
exit 1
