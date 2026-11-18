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
> platform, the hunting function it serves, and the threat landscape it hunts.

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
| R-08 | Internal | Hunting programme (analyst time, hunt backlog) | Hunts are ad hoc and not tied to current intelligence, so an active APT keeps a long dwell time | — | No record of which hypotheses exist, what they cover, or why one runs before another | 4 | 4 | 16 (High) | Hunts as code: `hunts/H-xxx.yaml` records hypothesis, ATT&CK techniques, data sources and rule; MISP campaign data reorders the hunt queue | 2 | 4 | 8 (Medium) | `hunts/`; `scripts/prioritise_hunts.py` | Open |
| R-09 | Internal | Detection rule set | A rule edit or schema change silently stops a hunt matching (false negative) | — | Rules shipped without samples or tests | 3 | 4 | 12 (Medium) | Every hunt rule ships a positive and a negative sample; pytest asserts match and no-match on every pull request | 1 | 4 | 4 (Low) | `tests/test_hunts.py`; `hunts/samples/`; `.github/workflows/ci.yml` | Open |
| R-10 | External | Engineering workstations and domain controllers at the IT/OT boundary | APT living off the land with built-in tools (WMI, PowerShell, ntdsutil) to stage access to OT | T1047; T1059.001; T1003.003 | Native admin tools look legitimate and no behavioural rule watches them | 4 | 5 | 20 (High) | Sigma hunts for the technique chain on Sysmon/Windows telemetry in OpenSearch | 3 | 4 | 12 (Medium) | `hunts/H-001.yaml` to `hunts/H-003.yaml`; `docs/evidence/` | Open |
| R-11 | External | Hosts sending telemetry to the SOC | Contact with infrastructure already attributed to an APT goes unflagged | T1071; T1105 | Telemetry is not compared with current threat intelligence | 4 | 4 | 16 (High) | PyMISP pulls APT indicators into a lookup; matching events are tagged `threat.indicator.matched` and their risk score raised | 2 | 3 | 6 (Low) | `scripts/misp_pull.py`; `enrich/`; `docs/evidence/` | Open |
| R-12 | External | The SOC's own public-facing address | A service exposed by mistake is indexed by Shodan and used for initial access | T1595.002; T1190 | No outside-in view of what the SOC exposes | 3 | 3 | 9 (Medium) | Scheduled Shodan query on the owned IP; a new port or banner is flagged | 1 | 3 | 3 (Low) | `scripts/exposure_check.py`; `docs/evidence/` | Open |
| R-13 | Operational | Detection rules drafted with an LLM from threat reports | Poisoned threat intelligence (a crafted MISP event or report) prompt-injects the LLM into writing a blind or weakened rule | ATLAS AML.T0051.001 (Indirect Prompt Injection) | Threat-report text is untrusted input but the LLM treats it as instruction | 3 | 5 | 15 (High) | LLM output arrives only as a pull request; the positive-sample test fails a blind rule; CODEOWNERS review; the LLM gets no tool access to MISP or OpenSearch | 2 | 3 | 6 (Low) | `tests/test_hunts.py`; `CODEOWNERS`; `docs/ai-governance.md` | Open |

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

## Evidence notes

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
