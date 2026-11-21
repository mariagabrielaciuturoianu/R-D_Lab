# Risk Register

Written before the code it governs. Every control in this repository answers a row here,
and every commit and pull request cites the risk IDs it addresses.

Three registers are in scope. **Operational** risk is introduced by the AI agent and the
Git CLI in the engineering workflow. **Internal** risk sits in the security function the
project serves. **External** risk comes from the live threat landscape.

Likelihood (L) and impact (I) are scored 1 to 5 (see [Scales](#scales)). Inherent score is
L x I. Residual score (RL x RI) is scored again with the control in place. A row marked
Implemented or Verified points to something a reviewer can open in the clone.

**Project.** A hypothesis-driven APT hunting platform for a critical-infrastructure SOC.
Hunts are code: each hypothesis names an APT behaviour, its ATT&CK techniques, the data it
needs and a tested Sigma rule. MISP threat intelligence decides which hypotheses to hunt
first and raises the risk score of telemetry that touches known APT infrastructure.

> Rows R-01 to R-06 cover the governed AI workflow. Rows R-07 to R-13 cover the SOC
> platform, the hunting function it serves, and the threat landscape it hunts. R-15 to
> R-17 cover the CI/CD pipeline and the artefact it ships. R-14
> records residual exposure of the public repository, accepted after review.

## Register

| ID | Register | Asset | Threat / technique | ATT&CK / ATLAS | Vulnerability | L | I | Inherent | Control | RL | RI | Residual | Evidence | Status |
|----|----------|-------|--------------------|----------------|---------------|---|---|----------|---------|----|----|----------|----------|--------|
| R-01 | Operational | `main` branch | AI agent or student lands unreviewed code on `main` | — | Agent holds push rights; no server-side gate on a Free private repo | 4 | 4 | 16 (High) | Local `no-commit-to-branch` hook; PreToolUse hook refuses agent `git push` to `main`; governance workflow fails any commit on `main` without a merged PR; CODEOWNERS review | 1 | 4 | 4 (Low) | `.pre-commit-config.yaml`; `.claude/hooks/guard.sh`; `.github/workflows/governance.yml`; `CODEOWNERS`; `docs/evidence/R-01-no-commit-to-branch.png`; `docs/evidence/R-01-governance-green.png`; `tests/test_guard_hook.py` | Verified |
| R-02 | Operational | Repository secrets (tokens, admin passwords, private keys) | Plaintext secret committed and pushed from the CLI | T1552.001 | No scanning before commit; secrets kept as plaintext files | 4 | 5 | 20 (High) | gitleaks and `detect-private-key` in pre-commit; GitHub push protection; `.gitignore` for env and key files; SOPS/age ciphertext only (Lab 3) | 2 | 3 | 6 (Low) | `.pre-commit-config.yaml`; `.gitignore`; `.sops.yaml`; `secrets/opensearch.enc.yaml`; `tests/test_guard_hook.py` (`--no-verify` refused); `docs/evidence/R-02-gitleaks-blocks-commit.txt`; `docs/evidence/R-02-sops-ciphertext.jpg` | Verified |
| R-03 | Operational | Git history of `main` | `git push --force` rewrites or erases reviewed history | T1565.001 | Force push allowed by default on unprotected branches | 3 | 4 | 12 (Medium) | PreToolUse hook and `deny` rule refuse agent force pushes; governance workflow flags commits on `main` not from a merged PR; CONTRIBUTING forbids force push | 1 | 4 | 4 (Low) | `.claude/settings.json`; `.claude/hooks/guard.sh`; `CONTRIBUTING.md`; `tests/test_guard_hook.py`; `docs/evidence/R-01-R-06-guard-hook-tests.txt`; `docs/evidence/R-05-hook-blocks-poisoned-push.png` | Verified |
| R-04 | Operational | GitHub credentials used by the CLI and CI | Leaked or stolen over-scoped token reaches other repositories | T1078.004 | Classic PAT with `repo` scope across all repositories | 3 | 5 | 15 (High) | Fine-grained PAT scoped to this repository, short expiry; workflows declare least-privilege `permissions:` | 2 | 2 | 4 (Low) | `CONTRIBUTING.md`; `.github/workflows/governance.yml` (`permissions:` block); `docs/evidence/R-04-token-lacks-workflow-scope.png` | Verified |
| R-05 | Operational | AI configuration (`CLAUDE.md`, `.claude/memory/`, `.claude/skills/`) | Memory poisoning: a planted instruction steers later sessions to weaken a control, push to `main` or approve its own change | ATLAS AML.T0080 (AI Agent Context Poisoning) | Memory and skill files are loaded as trusted context every session | 3 | 5 | 15 (High) | Memory and skills reviewed in PRs via CODEOWNERS; safety-critical rules enforced by `deny` rules and a PreToolUse hook, not prose | 2 | 3 | 6 (Low) | `CODEOWNERS`; `.claude/settings.json`; `.claude/hooks/guard.sh`; `docs/ai-governance.md`; `docs/evidence/R-01-R-06-guard-hook-tests.txt`; `docs/evidence/R-05-hook-blocks-poisoned-push.png`; `docs/evidence/R-05-hook-self-protection.png` | Verified |
| R-06 | Operational | Decrypted secrets on the workstation (`.env*`, `secrets/`, keys) | Agent reads a secret file into its context and leaks it in output, a commit or a prompt | T1552.001 | Agent has unrestricted file read in the working tree | 3 | 5 | 15 (High) | `deny` rules on secret paths; PreToolUse hook blocks Read/Edit/Write and shell access to them | 1 | 5 | 5 (Low) | `.claude/settings.json`; `.claude/hooks/guard.sh`; `docs/evidence/R-06-hook-blocked-agent-live.txt`; `docs/evidence/R-06-hook-blocks-secret-read.png`; `docs/evidence/R-01-R-06-guard-hook-tests.txt` | Verified |
| R-07 | Internal | SOC data store (OpenSearch) and analyst console (Dashboards) | Intruder on the host network reads or tampers with hunt telemetry, or reaches an unauthenticated console | T1557; T1565.001 | Plaintext links between components; services bound on all interfaces; mutable image tags | 3 | 4 | 12 (Medium) | mTLS between components with leaf certificates from a local root CA (OpenSearch requires a client certificate); host ports bound to 127.0.0.1 from `config/stack.env`; images pinned by arm64 digest; passwords as SOPS ciphertext, OpenSearch receives bcrypt hashes only | 1 | 4 | 4 (Low) | `compose.yaml`; `config/opensearch.yml`; `config/opensearch_dashboards.yml`; `scripts/pki.sh`; `scripts/render-runtime.sh`; `Makefile` (`deploy`, `destroy`, `health`); `tests/test_compose_policy.py`; `docs/evidence/R-07-deploy-health-two-runs.txt`; `docs/evidence/R-07-certificates.png`; `docs/evidence/R-07-dashboard.png` | Verified |
| R-08 | Internal | Hunting programme (analyst time, hunt backlog) | Hunts are ad hoc and not tied to current intelligence, so an active APT keeps a long dwell time | — | No record of which hypotheses exist, what they cover, or why one runs before another | 4 | 4 | 16 (High) | Hunts as code: `hunts/H-xxx.yaml` records hypothesis, ATT&CK techniques, data sources and rule; MISP campaign data reorders the hunt queue | 2 | 4 | 8 (Medium) | `hunts/H-001.yaml` to `hunts/H-003.yaml` (hypothesis, techniques, threat actors, confirm/refute criteria, base priority); `tests/test_hunts.py` (`test_hunt_is_complete`); `scripts/intel_lib.py` (`prioritise`); `tests/test_intel.py`; `docs/evidence/R-11-misp-enrichment.txt` (queue H-003 > H-001 > H-002 becomes H-001 > H-003 > H-002 with Sandworm active) | Verified |
| R-09 | Internal | Detection rule set | A rule edit or schema change silently stops a hunt matching (false negative) | — | Rules shipped without samples or tests | 3 | 4 | 12 (Medium) | Every hunt rule ships a positive and a negative sample; pytest asserts match and no-match on every pull request | 1 | 4 | 4 (Low) | `tests/test_hunts.py`; `tests/sigma_match.py`; `tests/samples/hunts/`; `detections/opensearch/` (committed queries, reconverted in every test run); `.github/workflows/ci.yml` (`test`); `docs/evidence/R-13-weakened-rule-fails-tests.txt` | Verified |
| R-10 | External | Engineering workstations and domain controllers at the IT/OT boundary | APT living off the land with built-in tools (WMI, PowerShell, ntdsutil) to stage access to OT | T1047; T1059.001; T1003.003 | Native admin tools look legitimate and no behavioural rule watches them | 4 | 5 | 20 (High) | Sigma hunts for the technique chain on Sysmon/Windows telemetry in OpenSearch | 3 | 4 | 12 (Medium) | `detections/sigma/H-001-wmi-spawns-shell.yml`; `detections/sigma/H-002-encoded-powershell.yml`; `detections/sigma/H-003-ntdsutil-ifm.yml`; `config/opensearch/hunt-telemetry-template.json`; `scripts/run_hunts.py`; `docs/evidence/R-10-hunts-against-opensearch.txt`; `docs/evidence/R-10-dashboards-hunt-H-003.jpg` | Verified |
| R-11 | External | Hosts sending telemetry to the SOC | Contact with infrastructure already attributed to an APT goes unflagged | T1071; T1105 | Telemetry is not compared with current threat intelligence | 4 | 4 | 16 (High) | PyMISP pulls APT indicators into a lookup; matching events are tagged `threat.indicator.matched` and their risk score raised | 2 | 3 | 6 (Low) | `compose.misp.yaml`; `scripts/intel.py`; `scripts/intel_lib.py` (`build_lookup`, `enrich`); `tests/test_intel.py`; `config/opensearch/intel-telemetry-template.json`; `docs/evidence/R-11-misp-enrichment.txt`; `docs/evidence/R-11-misp-event-summary.jpg`; `docs/evidence/R-11-misp-event-attributes.jpg` | Verified |
| R-12 | External | The SOC's own public-facing address | A service exposed by mistake is indexed by Shodan and used for initial access | T1595.002; T1190 | No outside-in view of what the SOC exposes | 3 | 3 | 9 (Medium) | Scheduled Shodan query on the owned IP; a new port or banner is flagged | 1 | 3 | 3 (Low) | `scripts/exposure_check.py`; `scripts/intel_lib.py` (`exposure_change`, `mask_ip`); `tests/test_intel.py`; `docs/evidence/R-12-shodan-exposure.png` | Verified |
| R-13 | Operational | Detection rules drafted with an LLM from threat reports | Poisoned threat intelligence (a crafted MISP event or report) prompt-injects the LLM into writing a blind or weakened rule | ATLAS AML.T0051.001 (Indirect Prompt Injection) | Threat-report text is untrusted input but the LLM treats it as instruction | 3 | 5 | 15 (High) | LLM output arrives only as a pull request; the positive-sample test fails a blind rule; CODEOWNERS review; the LLM gets no tool access to MISP or OpenSearch | 2 | 3 | 6 (Low) | `tests/test_hunts.py`; `CODEOWNERS`; `docs/ai-governance.md`; `docs/evidence/R-13-weakened-rule-fails-tests.txt` | Verified |
| R-14 | Operational | Public repository content and metadata | Reconnaissance of the public repository: commit author email, superseded text kept in a merged pull request's original commits, password length inferred from SOPS ciphertext | T1593.003 | Repository is public by choice; GitHub keeps pull request commits after the branch is deleted; AES-GCM preserves plaintext length | 3 | 1 | 3 (Low) | Accepted. Public visibility approved by the instructor; nothing secret is committed (gitleaks history scan clean, keys and decrypted files git-ignored); the email is intended to be public; merged branches are deleted; passwords are at least 14 characters from 72 symbols, so length gives no practical advantage. Rotate to longer passwords with `FORCE=1 make secrets-init` if the threat model changes | 3 | 1 | 3 (Low) | `.gitignore`; `scripts/new-secret.sh`; `docs/evidence/R-02-gitleaks-blocks-commit.txt` | Accepted |
| R-15 | Operational | CI pipeline, its token and the artefacts it builds | A third-party action or CI tool release is replaced with code that steals secrets or tampers with builds (moved tags, as in the 2025 tj-actions and 2026 trivy-action compromises) | T1195.001 | Actions referenced by mutable tags; tools installed without versions; no audit of the workflow itself | 4 | 5 | 20 (High) | Every action pinned to a full commit SHA whose GitHub signature was verified at pin time, tag in a comment; scanner and linter versions pinned (Trivy binary, Semgrep, zizmor); zizmor audits every workflow; Dependabot proposes updates as pull requests after a 7-day cooldown; `tests/test_supply_chain.py` fails any unpinned `uses:` | 1 | 5 | 5 (Low) | `.github/workflows/ci.yml`; `.github/dependabot.yml`; `tests/test_supply_chain.py` | Implemented |
| R-16 | Operational | Repository secrets and the workflow write token | A fork pull request or a crafted branch or tag name runs attacker code with repository secrets or a write token ("pwn request", template injection) | T1528 | `pull_request_target`, write tokens by default, `${{ }}` expressions inside shell scripts, credentials persisted by checkout | 3 | 5 | 15 (High) | No `pull_request_target`; top-level token read-only and widened per job (release only); `persist-credentials: false` on every checkout; values reach shell only through `env:`; approval required for external contributors' workflows | 1 | 4 | 4 (Low) | `.github/workflows/ci.yml`; `tests/test_supply_chain.py`; repository Actions settings | Implemented |
| R-17 | Internal | Hunt toolkit image used by analysts (sigma-cli, PyMISP) | A vulnerable or tampered image reaches the analysts who run it | T1525; T1195.002 | Base images not pinned or scanned; artefacts not signed, so a swapped image is indistinguishable | 3 | 4 | 12 (Medium) | Base image pinned by digest; image runs as a non-root user and ships without pip; CI starts the built image and fails if sigma or PyMISP cannot load; Trivy blocks HIGH/CRITICAL fixable findings and scans compose, Dockerfile and workflow config; release signs the image by digest with keyless Cosign and attaches a Syft SPDX SBOM. Signing decision: keyless, because the repository is public and the Rekor transparency log entry adds nothing an observer cannot already see | 1 | 4 | 4 (Low) | `toolkit/Dockerfile`; `.github/workflows/ci.yml` (`scan`, `release`) | Implemented |

## How each control lands in the repository

**R-01.** On a GitHub Free private repository branch protection is unavailable, so the
rule is enforced in three places. `no-commit-to-branch` refuses the commit locally.
`.claude/hooks/guard.sh` refuses any `git push` by the agent that targets `main`.
`.github/workflows/governance.yml` runs on every push to `main` and fails when the commit
is not part of a merged pull request; its run history is the evidence.

**R-02.** gitleaks and `detect-private-key` run before every commit. `.gitignore` keeps
env files, keys and `certs/` out of the index. From Lab 3, real secrets exist in the tree
only as SOPS/age ciphertext under `secrets/`.

**R-03.** The agent cannot force push: `Bash(git push --force*)` and `Bash(git push -f*)`
are denied in `.claude/settings.json`, and the guard hook rejects every force-push flag
form, including `+refspec`.

**R-04.** The CLI authenticates with a fine-grained token limited to this repository.
Every workflow sets `permissions:` explicitly, so `GITHUB_TOKEN` gets read access only
unless a job widens it.

**R-05 and R-06.** See [docs/ai-governance.md](docs/ai-governance.md). Memory is context,
not policy: the rules that matter are enforced by the harness before a tool runs.

**R-07 (Lab 3).** The stack is declared in `compose.yaml` and built only by `make deploy`.
A local root CA issues a leaf certificate per component, so OpenSearch, Dashboards and the
front door authenticate each other with mTLS. Host ports come from `.env` and bind to
127.0.0.1. The admin password exists in git only as SOPS/age ciphertext.

**R-08 and R-09 (Lab 5).** A hunt is a YAML file, not a note in an analyst's head. It
names the hypothesis, the ATT&CK techniques and the Sigma rule, and ships a positive and a
negative sample. `tests/test_hunts.py` proves the rule fires on one and not the other, in
CI on every pull request.

**R-10 (Lab 5).** The first hunts follow a living-off-the-land chain typical of APTs that
pre-position in critical infrastructure: WMI and PowerShell execution, then credential
dumping with `ntdsutil`. The residual score stays Medium on purpose: behavioural hunts
reduce dwell time but cannot guarantee detection.

**R-11 and R-12 (Lab 6).** MISP is the live source. `scripts/misp_pull.py` pulls APT
indicators into the enrichment lookup; a matching event is tagged and its risk score rises,
while a clean event is untouched. That difference is the evidence that enrichment changes
an outcome. Shodan checks only the project's own address.

**R-13.** Any LLM, Claude Code included, that turns a threat report into a rule reads
attacker-controllable text. The control does not trust the model: the rule only lands
through a pull request, and a rule that no longer fires on its positive sample fails CI.

**R-15 to R-17 (Lab 4).** `.github/workflows/ci.yml` runs on every pull request. `lint`
(ShellCheck, Hadolint, Semgrep, zizmor) and `test` (pytest) run first; `scan` builds the
hunt toolkit on a native arm64 runner and lets Trivy fail the run on a HIGH or CRITICAL
fixable finding. On a `v*` tag, `release` pushes the image to GHCR, signs it by digest
with keyless Cosign (an OIDC identity from the workflow, a short-lived Fulcio certificate,
a public Rekor entry, no long-lived key to steal) and publishes the SBOM with the release.
On GitHub Free the checks cannot be made required; the project never merges a red pull
request, and the governance workflow plus the PR history prove it.

Dependabot's first run tested these gates. Its sigma-cli 4 proposals (#9, #10) failed
`scan`: sigma-cli 4 needs pySigma 2, which the OpenSearch backend does not support. Its
Python 3.15 base-image proposal (#8) passed every check, yet the image could not start
sigma (no compiled PyYAML for 3.15). A clean scan had proved the image safe, not that it
worked, so `scan` now starts the image before scanning it, and Dependabot ignores
sigma-cli majors and Python minors until they are moved deliberately.

## Evidence notes

- **R-11, enrichment that changes an outcome.** `R-11-misp-enrichment.txt` runs the whole
  chain against the live MISP and OpenSearch containers. Of 5 IP attributes in MISP, 2
  indicators survive the lifecycle: one is dropped as context only (`to_ids` false), one
  (a public resolver flagged on purpose) by MISP's warninglist, and the relay shared by two
  events is deduplicated. The two connections to the campaign's infrastructure are tagged
  `threat.indicator.matched` with risk 90 and the actor attached; the other three keep risk
  20 and gain nothing. MISP runs from pinned images on loopback with a certificate from the
  project root CA, its passwords and API key are generated straight into SOPS ciphertext,
  and live indicators stay in the git-ignored `enrich/`. The exercise events use RFC 5737
  documentation addresses, so no real third party is named. The MISP screenshots show the
  same lifecycle inside MISP: the IDS flag is off for the context-only address, the public
  resolver carries MISP's warninglist marker ("List of known IPv4 public DNS resolvers"),
  the relay correlates with the follow-up event, and the event is attributed to Sandworm
  Team with ATT&CK techniques and TLP:CLEAR.
- **R-12.** `R-12-shodan-exposure.png`: Shodan reports the address this machine is using
  (masked to its first two octets, as the public IP is personal data) and holds no record
  of it, so nothing exposed has been indexed; the snapshot is the baseline for alerts on
  newly exposed ports. Free Shodan plans may not call the host API, so the check falls
  back to Shodan InternetDB, the free per-IP view of the same scan data. InternetDB's CDN
  rejects Python's default User-Agent, so the tool identifies itself by name.
- **R-08.** With Sandworm Team active in MISP, hunts sharing that actor move up:
  H-001 3 -> 1 and H-002 4 -> 2, so the queue reorders from H-003 > H-001 > H-002 to
  H-001 > H-003 > H-002.

- **R-09 and R-13.** `R-13-weakened-rule-fails-tests.txt` applies two plausible bad edits to
  H-003, the kind a poisoned threat report could steer an LLM into: narrowing the match to
  `create full` and pointing the rule at a binary that never runs. Both fail CI with a
  "blind to" message naming the missed attack, and the committed query no longer matches
  its rule. The unmodified rule passes.
- **R-10.** `R-10-hunts-against-opensearch.txt` loads 16 sample events (positives and
  near-miss negatives) into the live stack and runs the committed queries over mTLS: every
  hunt finds all its positives and no negative. H-001 also fires on one H-002 positive,
  PowerShell launched through WMI, which is correct: attack chains share events. Process
  fields are indexed with a lowercase normaliser, so the queries match regardless of case,
  the same way the Python matcher compares values. Writing H-003's samples exposed a false
  negative in the first version of the rule (`create sysvol full`); the rule was widened
  and the sysvol form is now a positive sample.
- **R-07, strict PKI.** Python 3.13 verifies certificates against RFC 5280 strictly and
  rejected the Lab 3 leaves for lacking an Authority Key Identifier. `scripts/pki.sh` now
  adds subject and authority key identifiers and refuses to finish unless
  `openssl verify -x509_strict` accepts every leaf; `REISSUE=1 make pki` rotates the leaves.

- **Prose versus enforcement.** In the three `R-05`/`R-06` screenshots the model refuses on
  its own, citing `CLAUDE.md`; that shows the onboarding rules shaping behaviour, not the
  hook. Deterministic enforcement is shown by `R-06-hook-blocked-agent-live.txt`, where
  the harness blocked a live agent command before it ran, and by
  `tests/test_guard_hook.py`, which feeds the hook every blocked and allowed case on each
  `make test` (23 cases, `R-01-R-06-guard-hook-tests.txt`).
- **R-02.** `R-02-gitleaks-blocks-commit.txt` replays the repository's own pre-commit
  configuration against a staged fake GitHub token in a throwaway repository: gitleaks
  fails with rule `github-pat` and no commit is created. GitHub server-side push protection
  is not available for private repositories on GitHub Free, so the local hook is the control.
- **R-04.** `R-04-token-lacks-workflow-scope.png` shows GitHub refusing a push because the
  fine-grained token was not granted the `workflow` permission: the token carries only what
  it was explicitly given.
- **R-07.** `R-07-deploy-health-two-runs.txt` is two full `destroy`, `deploy`, `health`
  cycles from nothing. Both reach yellow, the expected ceiling on one node because replica
  shards have no second node, and both show a caller without a client certificate refused
  during the TLS handshake.

## Scales

| Score | Likelihood | Impact |
|-------|-----------|--------|
| 1 | Rare: no realistic path with current controls | Negligible: no effect on C, I or A |
| 2 | Unlikely: needs unusual conditions or insider error | Minor: contained, fixed in hours, no data exposure |
| 3 | Possible: plausible within the project lifetime | Moderate: one component degraded, limited exposure |
| 4 | Likely: expected without the control | Major: detections blind or secrets exposed |
| 5 | Almost certain: already observed or trivially triggered | Severe: full compromise of the project or its credentials |

Score bands on L x I: 1-7 Low, 8-14 Medium, 15-25 High.

## Status values

Open, Implemented (control exists), Verified (evidence reviewed and stored in
`docs/evidence/`), Accepted (risk left as is, with the reason in the Control column).
