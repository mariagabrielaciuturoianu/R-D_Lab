# R&D Lab: AI-Driven Security Engineering

Project repository for Risk and Damage Management, Module 4A (ULBS Cybersecurity Master).
Engineering is driven by AI configuration authored in this repository, and every change,
human or agent, arrives through a governed pull request.

> **Project theme:** to be fixed. Scope and the internal/external risks follow from
> rows R-07 onward in [RISK-REGISTER.md](RISK-REGISTER.md).

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

**GitHub plan route:** 4, GitHub Free with evidence-based governance (local hook plus the
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
pre-commit install   # once per clone
make lint            # pre-commit on all files
make test            # tests (added with the project components)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
