---
name: check
description: Run lint and tests, summarise failures by file, propose the smallest fix. Use before committing or when asked to validate the repository.
---

1. Run `make lint`, then `make test`. Run both even if the first fails.
2. If both pass, report one line per command and stop.
3. Group failures by file. For each, quote the failing line and name the hook or test.
4. Map each failure to the risk it guards (gitleaks and detect-private-key: R-02,
   no-commit-to-branch: R-01, tests: the row they cite).
5. Propose the minimal change. Do not apply it without confirmation.
6. Never bypass a failing hook with `--no-verify` or by editing `.pre-commit-config.yaml`.
