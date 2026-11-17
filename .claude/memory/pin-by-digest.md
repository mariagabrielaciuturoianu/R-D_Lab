---
name: pin-by-digest
description: Container images pinned by sha256 digest; GitHub Actions and pre-commit hooks pinned by full commit SHA
metadata:
  type: feedback
---

Images: `name@sha256:<digest>` for the `linux/arm64` platform, with `# name:tag` above.
Actions: `uses: owner/action@<40-char SHA>  # vX.Y.Z`. Pre-commit: `rev: <SHA>  # vX.Y.Z`.

**Why:** A tag is mutable; whoever controls it controls what runs (supply-chain risk, Lab 4).
**How to apply:** Resolve the digest or SHA from the registry or `git ls-remote`; never invent one.
