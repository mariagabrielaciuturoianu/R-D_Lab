#!/bin/bash
# Create secrets/opensearch.enc.yaml interactively (R-02).
# Passwords are read without echo, never written to disk in plaintext, never in shell
# history, and piped straight into sops, so only age ciphertext reaches the repository.
set -euo pipefail

OUT=secrets/opensearch.enc.yaml
# Characters that survive YAML, dotenv and curl config quoting unchanged.
ALLOWED='^[A-Za-z0-9!@%^*_+=-]{14,}$'

if [ -f "$OUT" ] && [ "${FORCE:-}" != "1" ]; then
  echo "$OUT exists; rerun with FORCE=1 to rotate both passwords." >&2
  exit 1
fi

ask() {
  local label=$1 a b
  while :; do
    printf '%s: ' "$label" >&2; read -rs a; echo >&2
    printf 'Repeat: ' >&2; read -rs b; echo >&2
    if [ "$a" != "$b" ]; then echo "Mismatch, try again." >&2; continue; fi
    if ! [[ $a =~ $ALLOWED ]]; then
      echo "Use at least 14 characters from A-Z a-z 0-9 ! @ % ^ * _ + = -" >&2; continue
    fi
    printf '%s' "$a"; return
  done
}

ADMIN=$(ask "OpenSearch admin password")
DASH=$(ask "Dashboards server (kibanaserver) password")
if [ "$ADMIN" = "$DASH" ]; then echo "Use two different passwords." >&2; exit 1; fi

mkdir -p secrets
printf 'OPENSEARCH_ADMIN_PASSWORD: "%s"\nDASHBOARDS_SERVER_PASSWORD: "%s"\n' "$ADMIN" "$DASH" \
  | sops --encrypt --filename-override "$OUT" --input-type yaml --output-type yaml /dev/stdin \
  > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
unset ADMIN DASH
echo "Wrote $OUT (ciphertext only). Commit it; never commit a decrypted copy."
