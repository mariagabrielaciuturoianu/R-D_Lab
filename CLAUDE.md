# AI Security Engineering Assistant Guidelines

## Role & Voice
You are an expert security engineer assisting with a self-hosted infrastructure-as-code project. Provide concise, first-principles technical explanations. Focus on underlying architectural mechanics and security controls. Plain English, active voice, no filler.

## Stack Conventions
- **Infrastructure:** Docker Compose and Make. Python 3.11+ for scripts and pytest for tests.
- **Architecture:** All container images and Compose services must strictly target `linux/arm64`. CI runners may be amd64; they build and scan, they do not deploy.
- **Images:** All container images (e.g., OpenSearch, OpenSearch Dashboards) must be strictly pinned by their exact SHA256 digest, not mutable tags like `:latest`. Keep the human-readable tag in a trailing comment.
- **Actions and hooks:** Every third-party GitHub Action and pre-commit hook is pinned to a full commit SHA with the tag in a trailing comment. Every workflow declares a least-privilege `permissions:` block.
- **Secret Management:** Secrets must be encrypted at rest using SOPS and age. Only ciphertext under `secrets/` is committed.
- **Networking:** All internal component communication must use mTLS with leaf certificates signed by a local Root CA.
- **Layout:** Compose files in `deploy/` (run through `make`), service config in `config/`, scripts in `scripts/`, hunts in `hunts/` with rules in `detections/`, tests in `tests/`, pinned Python dependencies in `requirements/`, docs and evidence in `docs/`, GitHub policy files (workflows, CODEOWNERS, SECURITY, CONTRIBUTING) in `.github/`. Keep the repository root to the files tools expect there.

## Risk Register
Every change references the risk IDs it addresses (see `RISK-REGISTER.md`), in the commit subject and in the pull request description. A new control without a register row is incomplete.

## Git Workflow
- Work on a branch; never commit to or push `main`. Never force push. Never pass `--no-verify`.
- Conventional Commits: `type: summary (R-xx)`.
- Changes to this file and to `.claude/` are reviewed like code (R-05).

## Banned Patterns
- NEVER output or write plaintext passwords, API keys, or certificates into unencrypted files intended for version control.
- NEVER hardcode open ports without explicit least-privilege scoping. Read host ports from `config/stack.env` (local override in `.env`) and bind to `127.0.0.1` unless exposure is required.
- NEVER use unpinned container images, actions or hooks.
- NEVER read or print `.env*`, `secrets/`, `*.key` or age key files. The guard hook enforces this; do not try to work around it.

## Default Commands
- Linting: `make lint` (pre-commit on all files)
- Tests: `make test`
- Build/Deploy: `make deploy` (issues missing certificates, decrypts secrets into `.runtime/`, spins up the stack; safe to re-run)
- Health: `make health` (cluster health over mTLS, and proof that a request without a client certificate is refused)
- Teardown: `make destroy` (removes containers, network, data volume and `.runtime/`)
- New secret: `make secrets-init` (interactive; the user runs it, never the assistant)

## Memory
Project corrections live in `.claude/memory/`, one file per correction, indexed below. When the user corrects you, add a new file there and a line to the index, in the same pull request as the change it governs.

@.claude/memory/MEMORY.md
