# Contributing

Every change, from a person or an AI agent, follows the same path. Each rule below answers
a row in [RISK-REGISTER.md](../RISK-REGISTER.md).

## Workflow

1. Install the hooks once per clone: `pre-commit install`.
2. Branch from `main`: `git switch -c <type>/<short-name>`. Commits on `main` are refused
   locally by `no-commit-to-branch` (R-01).
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/) and cite the
   risk IDs the change addresses, for example `feat: encrypted admin secret (R-02)`.
4. Run `make lint` before pushing. gitleaks must pass (R-02).
5. Push the branch and open a pull request. The description lists the risk IDs it closes.
6. A `CODEOWNERS` reviewer approves before merge. Never push to `main` and never
   `--force` push a shared branch (R-01, R-03).

## Credentials

Use a fine-grained personal access token scoped to this repository only, with the
shortest expiry that fits the task (R-04). Never paste a token into a file, a commit
message, an issue or an AI prompt. Secrets live only as SOPS ciphertext under `secrets/`.

## AI agent contributions

AI agents follow the same workflow and the extra rules in [SECURITY.md](SECURITY.md).
Changes to `CLAUDE.md`, `.claude/` (memory, skills, hooks, settings) are reviewed exactly
like code, because they steer every later agent session (R-05).
