---
name: no-plaintext-secrets
description: Secrets exist in git only as SOPS/age ciphertext; never read or echo decrypted env files or keys
metadata:
  type: feedback
---

Real secrets live in `secrets/*.enc.yaml`, decrypted only by `make deploy` into an
owner-only file that `make destroy` deletes. Never open `.env*`, `secrets/`, `*.key`
or `~/.config/sops/age/keys.txt`, and never ask the user to paste a secret.

**Why:** Anything in agent context can leak into output, commits or prompts (R-02, R-06).
**How to apply:** Reference variables by name (`${OPENSEARCH_INITIAL_ADMIN_PASSWORD}`), never by value.
