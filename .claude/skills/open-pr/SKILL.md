---
name: open-pr
description: Validate the branch, check risk-ID citations, push the branch and open a pull request against main. Use when the user asks to ship, push or open a PR.
---

1. Confirm the current branch is not `main` (`git branch --show-current`). If it is, stop.
2. Run the `check` skill. Stop on any failure.
3. List the commits ahead of `origin/main` (`git log --oneline origin/main..HEAD`).
   Every subject must follow Conventional Commits and cite at least one `R-xx` that exists
   in `RISK-REGISTER.md`. Report any that do not and stop.
4. Show the user the branch name, the commit list and the draft PR description below,
   and wait for an explicit go-ahead before pushing.
5. Push the branch only: `git push -u origin <branch>`. Never force push.
6. Open the PR with `gh pr create --base main --head <branch>` using the description.
   If `gh` is not installed, print the compare URL
   `https://github.com/mariagabrielaciuturoianu/R-D_Lab/compare/main...<branch>`.

PR description template:

```
## Summary
<one paragraph: what changes and why>

## Risks addressed
- R-xx: <control> — evidence: `<path>`

## Checks
- [ ] make lint
- [ ] make test
- [ ] CODEOWNERS review
```
