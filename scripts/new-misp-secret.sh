#!/bin/bash
# Generate MISP's service passwords and admin API key at random and encrypt them straight
# into secrets/misp.enc.yaml (R-02). Nobody types or sees them: the admin key reaches
# scripts only through .runtime/ at deploy time. Rotate with FORCE=1.
set -euo pipefail

OUT=secrets/misp.enc.yaml
if [ -f "$OUT" ] && [ "${FORCE:-}" != "1" ]; then
  echo "$OUT exists; rerun with FORCE=1 to rotate every MISP secret." >&2
  exit 1
fi

# rnd <length>: alphanumeric only, so values survive YAML, dotenv and PHP config unchanged.
rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }

mkdir -p secrets
{
  # MISP enforces a password policy: upper, lower, digit and a special character.
  printf 'MISP_ADMIN_PASSWORD: "%s"\n' "$(rnd 24)Aa1!"
  printf 'MISP_ADMIN_KEY: "%s"\n' "$(rnd 40)"
  printf 'MISP_MYSQL_PASSWORD: "%s"\n' "$(rnd 32)"
  printf 'MISP_MYSQL_ROOT_PASSWORD: "%s"\n' "$(rnd 32)"
  printf 'MISP_REDIS_PASSWORD: "%s"\n' "$(rnd 32)"
} | sops --encrypt --filename-override "$OUT" --input-type yaml --output-type yaml /dev/stdin \
  > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "Wrote $OUT (ciphertext only, values never displayed). Commit it."
