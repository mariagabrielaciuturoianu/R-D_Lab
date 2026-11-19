#!/bin/bash
# Decrypt the SOPS secret into .runtime/ for one deployment (R-02, R-07).
#   .runtime/.env.secrets      dotenv for compose interpolation (Dashboards server password)
#   .runtime/internal_users.yml  bcrypt hashes only; OpenSearch never sees a plaintext password
# .runtime/ is git-ignored, owner-only, and deleted by `make destroy`.
set -euo pipefail

SRC=${SECRET_FILE:-secrets/opensearch.enc.yaml}
RUN=.runtime
[ -f "$SRC" ] || { echo "$SRC missing: run make secrets-init" >&2; exit 1; }

umask 077
mkdir -p "$RUN"
sops --decrypt --output-type dotenv "$SRC" > "$RUN/.env.secrets"

set -a
# shellcheck source=/dev/null
. "$RUN/.env.secrets"
set +a

# htpasswd reads the password on stdin (-i), so it never appears in the process list.
bcrypt() { printf '%s' "$1" | htpasswd -niBC 12 x | cut -d: -f2-; }

cat > "$RUN/internal_users.yml" <<EOF
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "$(bcrypt "$OPENSEARCH_ADMIN_PASSWORD")"
  reserved: true
  backend_roles: ["admin"]
  description: "Cluster administrator (all_access via backend role)"
kibanaserver:
  hash: "$(bcrypt "$DASHBOARDS_SERVER_PASSWORD")"
  reserved: true
  description: "Dashboards server user (kibana_server role only)"
EOF
# The OpenSearch container (uid 1000) must read the hash file through the bind mount.
chmod 644 "$RUN/internal_users.yml"
echo "rendered $RUN (secrets decrypted for this deployment only)"
