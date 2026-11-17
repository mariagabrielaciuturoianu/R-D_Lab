# Risk Register

Written before the code it governs. Every control in this repository answers a row here,
and every commit and pull request cites the risk IDs it addresses.

Three registers are in scope. **Operational** risk is introduced by the AI agent and the
Git CLI in the engineering workflow. **Internal** risk sits in the security function the
project serves. **External** risk comes from the live threat landscape.

Likelihood (L) and impact (I) are scored 1 to 5 (see [Scales](#scales)). Inherent score is
L x I. Residual score (RL x RI) is scored again with the control in place. A row marked
Implemented or Verified points to something a reviewer can open in the clone.

> Rows R-01 to R-06 cover the governed AI workflow and apply to any project theme.
> Rows R-07 onward are reserved for the internal and external risks of the project theme
> and are filled in when the theme is fixed.

## Register

| ID | Register | Asset | Threat / technique | ATT&CK / ATLAS | Vulnerability | L | I | Inherent | Control | RL | RI | Residual | Evidence | Status |
|----|----------|-------|--------------------|----------------|---------------|---|---|----------|---------|----|----|----------|----------|--------|
| R-01 | Operational | `main` branch | AI agent or student lands unreviewed code on `main` | — | Agent holds push rights; no server-side gate on a Free private repo | 4 | 4 | 16 (High) | Local `no-commit-to-branch` hook; PreToolUse hook refuses agent `git push` to `main`; governance workflow fails any commit on `main` without a merged PR; CODEOWNERS review | 1 | 4 | 4 (Low) | `.pre-commit-config.yaml`; `.claude/hooks/guard.sh`; `.github/workflows/governance.yml`; `CODEOWNERS` | Implemented |
| R-02 | Operational | Repository secrets (tokens, admin passwords, private keys) | Plaintext secret committed and pushed from the CLI | T1552.001 | No scanning before commit; secrets kept as plaintext files | 4 | 5 | 20 (High) | gitleaks and `detect-private-key` in pre-commit; GitHub push protection; `.gitignore` for env and key files; SOPS/age ciphertext only (Lab 3) | 2 | 3 | 6 (Low) | `.pre-commit-config.yaml`; `.gitignore` | Implemented |
| R-03 | Operational | Git history of `main` | `git push --force` rewrites or erases reviewed history | T1565.001 | Force push allowed by default on unprotected branches | 3 | 4 | 12 (Medium) | PreToolUse hook and `deny` rule refuse agent force pushes; governance workflow flags commits on `main` not from a merged PR; CONTRIBUTING forbids force push | 1 | 4 | 4 (Low) | `.claude/settings.json`; `.claude/hooks/guard.sh`; `CONTRIBUTING.md` | Implemented |
| R-04 | Operational | GitHub credentials used by the CLI and CI | Leaked or stolen over-scoped token reaches other repositories | T1078.004 | Classic PAT with `repo` scope across all repositories | 3 | 5 | 15 (High) | Fine-grained PAT scoped to this repository, short expiry; workflows declare least-privilege `permissions:` | 2 | 2 | 4 (Low) | `CONTRIBUTING.md`; `.github/workflows/governance.yml` (`permissions:` block) | Implemented |
| R-05 | Operational | AI configuration (`CLAUDE.md`, `.claude/memory/`, `.claude/skills/`) | Memory poisoning: a planted instruction steers later sessions to weaken a control, push to `main` or approve its own change | ATLAS AML.T0080 (AI Agent Context Poisoning) | Memory and skill files are loaded as trusted context every session | 3 | 5 | 15 (High) | Memory and skills reviewed in PRs via CODEOWNERS; safety-critical rules enforced by `deny` rules and a PreToolUse hook, not prose | 2 | 3 | 6 (Low) | `CODEOWNERS`; `.claude/settings.json`; `.claude/hooks/guard.sh`; `docs/ai-governance.md` | Implemented |
| R-06 | Operational | Decrypted secrets on the workstation (`.env*`, `secrets/`, keys) | Agent reads a secret file into its context and leaks it in output, a commit or a prompt | T1552.001 | Agent has unrestricted file read in the working tree | 3 | 5 | 15 (High) | `deny` rules on secret paths; PreToolUse hook blocks Read/Edit/Write and shell access to them | 1 | 5 | 5 (Low) | `.claude/settings.json`; `.claude/hooks/guard.sh` | Implemented |
| R-07 | Internal | _Defined with the project theme_ | | | | | | | | | | | | Open |
| R-08 | Internal | _Defined with the project theme_ | | | | | | | | | | | | Open |
| R-09 | External | _Defined with the project theme (MISP enrichment, Lab 6)_ | | | | | | | | | | | | Open |
| R-10 | External | _Defined with the project theme (external exposure, Lab 6)_ | | | | | | | | | | | | Open |

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
