#!/bin/bash
# Store the Shodan API key as SOPS ciphertext in secrets/intel.enc.yaml (R-02, R-12).
# The key is read without echo and piped straight into sops. Rotate with FORCE=1.
set -euo pipefail

OUT=secrets/intel.enc.yaml
if [ -f "$OUT" ] && [ "${FORCE:-}" != "1" ]; then
  echo "$OUT exists; rerun with FORCE=1 to replace the key." >&2
  exit 1
fi

printf 'Shodan API key (account.shodan.io): ' >&2
read -rs KEY; echo >&2
if ! [[ $KEY =~ ^[A-Za-z0-9]{20,64}$ ]]; then
  echo "That does not look like a Shodan API key." >&2
  exit 1
fi

mkdir -p secrets
printf 'SHODAN_KEY: "%s"\n' "$KEY" \
  | sops --encrypt --filename-override "$OUT" --input-type yaml --output-type yaml /dev/stdin \
  > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
unset KEY
echo "Wrote $OUT (ciphertext only). Commit it."
