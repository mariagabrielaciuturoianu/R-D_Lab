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

Scope and every control trace back to [RISK-REGISTER.md](RISK-REGISTER.md), the source of
truth. The same register in the course spreadsheet template, with its score formulas and
colour bands, is [docs/RISK-REGISTER.xlsx](docs/RISK-REGISTER.xlsx), regenerated with
`make register-xlsx` and kept in sync by `tests/test_register_export.py`.

**Stack:** OpenSearch and OpenSearch Dashboards (Docker Compose, arm64, pinned digests),
SOPS/age secrets, a local root CA for mTLS, Sigma and pytest, MISP with PyMISP, Shodan,
Prometheus and Alertmanager.

## Repository layout

```
.
├── CLAUDE.md            AI onboarding: role, conventions, banned patterns, commands
├── RISK-REGISTER.md     every control traces back to a row here
├── Makefile             the only entry point: deploy, test, hunt, intel, monitor ...
├── .claude/             memory, skills, settings and the PreToolUse guard hook
├── .github/             CI and review workflows, Dependabot, CODEOWNERS, SECURITY, CONTRIBUTING
├── config/              service configuration (OpenSearch, Prometheus, Alertmanager, ...)
├── deploy/              Compose files: SOC stack with monitoring, MISP
├── detections/          Sigma rules and their committed OpenSearch queries
├── docs/                evidence per risk ID, register spreadsheet, AI governance notes, archive
├── hunts/               hunt hypotheses H-001 ... (hunts as code)
├── requirements/        pinned Python dependencies: dev (CI), intel (local), review (CI)
├── scripts/             PKI, secrets, hunts, intel, exposure, alert demo, AI review
├── secrets/             SOPS/age ciphertext only
├── tests/               policy, hunt, intel and reviewer tests with samples
└── toolkit/             hunt toolkit image (sigma-cli, PyMISP)
```

## Governance (Labs 1 and 2)

| Control | Where | Risk |
|---|---|---|
| Local refusal of commits on `main` | `.pre-commit-config.yaml` (`no-commit-to-branch`) | R-01 |
| Commits on `main` without a merged PR fail CI | `.github/workflows/governance.yml` | R-01 |
| Mandatory human review, including AI config | `.github/CODEOWNERS` | R-01, R-05 |
| Secret scanning before commit | `.pre-commit-config.yaml` (gitleaks, detect-private-key) | R-02 |
| Agent cannot force push, push to `main`, or read secret paths | `.claude/settings.json`, `.claude/hooks/guard.sh` | R-01, R-03, R-06 |
| Least-privilege tokens | `.github/CONTRIBUTING.md`, workflow `permissions:` blocks | R-04 |
| Memory and skills reviewed like code | `.github/CODEOWNERS`, `docs/ai-governance.md` | R-05 |

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

## CI/CD pipeline (Lab 4)

`.github/workflows/ci.yml` runs on every pull request; a `v*` tag also releases.

| Job | What it blocks | Risk |
|---|---|---|
| `lint` / ShellCheck, Hadolint | Broken shell scripts, unsafe Dockerfile patterns | R-17 |
| `lint` / Semgrep (`p/ci`) | Known insecure code patterns | R-17 |
| `lint` / zizmor | Unpinned actions, persisted credentials, risky triggers, template injection, missing Dependabot cooldown | R-15, R-16 |
| `test` / pytest | Guard hook regressions, unpinned images or actions, loopback/mTLS policy drift | R-01..R-07, R-15, R-16 |
| `scan` / smoke test (arm64) | A toolkit image that builds but cannot run sigma or import PyMISP | R-17 |
| `scan` / Trivy (arm64) | Toolkit image with fixable HIGH/CRITICAL CVEs; misconfigured compose, Dockerfile or workflows | R-07, R-17 |
| `release` / Syft, Cosign | Unsigned or undocumented images reaching analysts | R-17 |

Dependabot (`.github/dependabot.yml`) proposes action, image and pip updates as pull
requests after a 7-day cooldown, so every update passes the same gates (R-15).

The `toolkit/` image bundles sigma-cli (OpenSearch backend) and PyMISP:

```bash
make toolkit                                   # build locally
docker run --rm hunt-toolkit:local list targets
```

## Hunts as code (Lab 5)

| Hunt | Hypothesis | ATT&CK | Rule |
|---|---|---|---|
| [H-001](hunts/H-001.yaml) | Lateral movement with remote WMI: shells under `WmiPrvSE.exe` | T1047 | `detections/sigma/H-001-wmi-spawns-shell.yml` |
| [H-002](hunts/H-002.yaml) | Staging hidden behind PowerShell `-EncodedCommand` | T1059.001, T1027.010 | `detections/sigma/H-002-encoded-powershell.yml` |
| [H-003](hunts/H-003.yaml) | Domain credential theft with `ntdsutil ... ifm create full` | T1003.003 | `detections/sigma/H-003-ntdsutil-ifm.yml` |

Each hunt names its threat actors, data sources and the result that confirms or refutes
it. Every rule ships positive samples and near-miss negatives in `tests/samples/hunts/`;
`tests/test_hunts.py` evaluates the rule file itself against them (via
`tests/sigma_match.py`) and fails if the committed OpenSearch query in
`detections/opensearch/` no longer equals the rule's conversion.

```bash
make queries         # reconvert every Sigma rule to OpenSearch query DSL
make test            # rule logic against samples, reconversion, sigma check
make hunt            # load samples into the running stack and run every committed query
```

## Threat intelligence (Lab 6)

MISP runs beside the SOC stack (`deploy/compose.misp.yaml`: database, cache, core, web front end;
pinned arm64 images, HTTPS on loopback, certificate from the project root CA). Its
passwords and admin API key are generated at random straight into SOPS ciphertext.

```bash
make misp-secrets    # once: random MISP passwords and API key -> secrets/misp.enc.yaml
make misp-up         # first boot takes several minutes; https://localhost:8444
make intel           # seed the exercise campaign, pull, enrich telemetry, reorder hunts
make intel-secret    # once: Shodan API key -> secrets/intel.enc.yaml
make exposure        # Shodan view of this machine's own public IP (masked in output)
make misp-down
```

| Step | What changes | Risk |
|---|---|---|
| Feed lifecycle | Only `to_ids` attributes, warninglists enforced, max 30 days old, deduplicated | R-11 |
| Enrichment | Telemetry touching a MISP indicator gets `threat.indicator.matched`, the actor, risk 20 -> 90 | R-11 |
| Hunt queue | Hunts whose threat actors are active in MISP move up | R-08 |
| Exposure | New open port on the project's own public IP raises an alert | R-12 |

Live indicators (`enrich/`) and exposure snapshots (`exposure/`) are git-ignored.

## Monitoring and automated review (Lab 7)

```bash
make monitor-up      # Prometheus https://localhost:9090, Alertmanager https://localhost:9093
make alert-demo      # stop OpenSearch, watch SocServiceDown fire and resolve
make monitor-down
```

Prometheus probes OpenSearch and Dashboards every 15 seconds through a blackbox prober.
Every machine-to-machine link (Prometheus to prober, prober to OpenSearch, Prometheus to
Alertmanager) is TLS from the project root CA with client certificates; the two web UIs
also accept the analyst's browser on loopback without one (accepted, see R-18). The prober's `monitor` certificate
completes the mTLS handshake but is granted no data, so monitoring needs no password.
Alerts: `SocServiceDown` (probe failing for 30s), `MonitoringTargetDown`,
`CertificateExpiresSoon` (14 days).

The `ai-review` workflow sends each same-repository pull request diff, with `CLAUDE.md` and
the register's risk IDs, to Claude and posts the review as a comment before the human
CODEOWNERS review. It needs the repository secret `ANTHROPIC_API_KEY` (skipped with a notice
otherwise); the optional repository variable `REVIEW_MODEL` selects the model (default
`claude-opus-5-5`; `claude-sonnet-5-5` or `claude-haiku-5-5` cost less). It runs on
`pull_request_target` with a base-only checkout, so the reviewer, its rules and its
hash-locked dependencies always come from `main`: a pull request cannot rewrite its own
reviewer or reach the key. The job may comment but never approve or merge, and treats the
diff as untrusted data. Changes to the reviewer itself take effect after they merge.

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
| Images pinned by linux/arm64 digest, ports on 127.0.0.1 from `config/stack.env` | `deploy/compose.yaml`, `tests/test_compose_policy.py` | R-07 |
| Root CA and leaf certificates per component (OpenSSL) | `scripts/pki.sh` (output in git-ignored `certs/`) | R-07 |
| mTLS: OpenSearch requires a client cert; Dashboards verifies the server and presents one | `config/opensearch.yml`, `config/opensearch_dashboards.yml` | R-07 |
| Passwords committed only as age ciphertext | `.sops.yaml`, `secrets/opensearch.enc.yaml` | R-02 |
| OpenSearch receives bcrypt hashes only; plaintext lives in `.runtime/` for one deployment | `scripts/render-runtime.sh`, `Makefile` | R-02 |

Dashboards: `https://localhost:5601`. Trust `certs/root-ca.pem` in your browser or accept
the warning once.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) and [SECURITY.md](.github/SECURITY.md).
