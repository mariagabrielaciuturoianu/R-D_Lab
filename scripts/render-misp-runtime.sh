#!/bin/bash
# Decrypt the MISP secrets (and the Shodan key, if present) into .runtime/.env.misp for one
# deployment (R-02). .runtime/ is git-ignored, owner-only, and removed by make misp-down.
set -euo pipefail

umask 077
mkdir -p .runtime
[ -f secrets/misp.enc.yaml ] || { echo "secrets/misp.enc.yaml missing: run make misp-secrets" >&2; exit 1; }
{
  sops --decrypt --output-type dotenv secrets/misp.enc.yaml
  if [ -f secrets/intel.enc.yaml ]; then
    sops --decrypt --output-type dotenv secrets/intel.enc.yaml
  fi
} > .runtime/.env.misp
echo "rendered .runtime/.env.misp (decrypted for this deployment only)"
