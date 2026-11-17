# Project memory index

One line per correction. Each file holds the rule, why it exists and how to apply it.
This index is imported by `CLAUDE.md`, so it is reviewed like code (R-05).

- [Never hardcode ports](never-hardcode-ports.md) — host ports come from `.env`, bound to 127.0.0.1 by default
- [Pin by digest or SHA](pin-by-digest.md) — images by `@sha256:`, actions and hooks by full commit SHA, tag in a comment
- [Cite risk IDs](cite-risk-ids.md) — every commit subject and PR description names the R-xx rows it addresses
- [No plaintext secrets](no-plaintext-secrets.md) — secrets only as SOPS/age ciphertext; never read `.env*` or `secrets/`
- [Reference repo is read-only](reference-repo-read-only.md) — cybrd0ne/secops-demo is for reading only; never commit or push there
