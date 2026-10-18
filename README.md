# Log-Enrichment Service

## Overview
This repository contains a small log-enrichment service. It serves as a hardened environment designed to safely integrate AI agents into the engineering loop while mitigating operational, internal, and external risks.

## Security Posture & Controls
* **Branch Protection:** Direct pushes and `--force` pushes to the `main` branch are blocked.
* **Mandatory Reviews:** All changes must arrive as a Pull Request and be approved by designated `CODEOWNERS`.
* **Secret Scanning:** A `gitleaks` pre-commit hook runs locally to prevent staging hardcoded credentials, backed by server-side Push Protection.
* **Least Privilege:** Interactions use fine-grained Personal Access Tokens (PATs) scoped exclusively to this project.
