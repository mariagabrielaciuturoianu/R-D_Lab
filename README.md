# APT Hunting as Code for Critical-Infrastructure SOCs

Project repository for Risk and Damage Management, Module 4A (ULBS Cybersecurity Master).
Engineering is driven by AI configuration authored in this repository, and every change,
human or agent, arrives through a governed pull request.

## What it does

A small self-hosted SOC platform for hypothesis-driven APT hunting:

1. **Hunts as code.** Each hunt in `hunts/` states a hypothesis about an APT behaviour,
   its ATT&CK techniques, the telemetry it needs and a Sigma rule, with a positive and a
   negative sample tested in CI.
2. **Intelligence decides the order.** MISP supplies APT campaigns and indicators. Active
   campaigns move matching hypotheses up the hunt queue; telemetry that touches known APT
   infrastructure is tagged and its risk score raised.
3. **Governed AI engineering.** Rules, pipelines and infrastructure are generated with an
   AI assistant under the controls in `CLAUDE.md` and `.claude/`, and land only through
   reviewed, tested pull requests.

Scope and every control trace back to [RISK-REGISTER.md](RISK-REGISTER.md).

**Stack:** OpenSearch and OpenSearch Dashboards (Docker Compose, arm64, pinned digests),
SOPS/age secrets, a local root CA for mTLS, Sigma and pytest, MISP with PyMISP, Shodan.

## Governance (Labs 1 and 2)

| Control | Where | Risk |
|---|---|---|
| Local refusal of commits on `main` | `.pre-commit-config.yaml` (`no-commit-to-branch`) | R-01 |
| Commits on `main` without a merged PR fail CI | `.github/workflows/governance.yml` | R-01 |
| Mandatory human review, including AI config | `CODEOWNERS` | R-01, R-05 |
| Secret scanning before commit | `.pre-commit-config.yaml` (gitleaks, detect-private-key) | R-02 |
| Agent cannot force push, push to `main`, or read secret paths | `.claude/settings.json`, `.claude/hooks/guard.sh` | R-01, R-03, R-06 |
| Least-privilege tokens | `CONTRIBUTING.md`, workflow `permissions:` blocks | R-04 |
| Memory and skills reviewed like code | `CODEOWNERS`, `docs/ai-governance.md` | R-05 |

**GitHub plan route:** GitHub Free with evidence-based governance (local hook plus the
governance workflow). Update this line if the repository moves to the ULBS organization
or GitHub Pro.

## AI configuration

- `CLAUDE.md`: role, voice, stack conventions, banned patterns, default commands.
- `.claude/memory/`: one file per correction, indexed by `MEMORY.md` and imported into
  `CLAUDE.md` so every session loads it.
- `.claude/skills/`: `check` (lint and tests) and `open-pr` (risk-cited pull request).
- `.claude/settings.json` and `.claude/hooks/guard.sh`: rules enforced by the harness.

## Commands

```bash
make hooks           # once per clone: install pre-commit hooks
make venv            # once per clone: pinned test dependencies
make lint            # pre-commit on all files
make test            # guard hook and compose policy tests
```

## Run the stack (Lab 3)

Requirements: Docker Desktop (arm64), `sops`, `age`, `openssl`, and an age key in
`~/.config/sops/age/keys.txt` whose public key is the recipient in `.sops.yaml`.

```bash
make secrets-init    # once: prompts for two passwords, writes SOPS ciphertext only
make deploy          # certificates, decrypt into .runtime/, start OpenSearch then Dashboards
make health          # green over mTLS; a request without a client cert is refused
make destroy         # containers, network, data volume and .runtime/ removed
```

| Piece | File | Risk |
|---|---|---|
| Images pinned by linux/arm64 digest, ports on 127.0.0.1 from `config/stack.env` | `compose.yaml`, `tests/test_compose_policy.py` | R-07 |
| Root CA and leaf certificates per component (OpenSSL) | `scripts/pki.sh` (output in git-ignored `certs/`) | R-07 |
| mTLS: OpenSearch requires a client cert; Dashboards verifies the server and presents one | `config/opensearch.yml`, `config/opensearch_dashboards.yml` | R-07 |
| Passwords committed only as age ciphertext | `.sops.yaml`, `secrets/opensearch.enc.yaml` | R-02 |
| OpenSearch receives bcrypt hashes only; plaintext lives in `.runtime/` for one deployment | `scripts/render-runtime.sh`, `Makefile` | R-02 |

Dashboards: `https://localhost:5601`. Trust `certs/root-ca.pem` in your browser or accept
the warning once.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
