# Security Policy

## Supported Versions
Only the latest commit on the `main` branch is actively supported and evaluated for security updates.

## AI Agent Contribution Policy
To mitigate operational and internal risks, all code generated or committed by AI agents (e.g., Claude Code, Gemini CLI) MUST adhere to the following strict controls:
1. **No Direct Pushes:** AI agents operate with restricted credentials and are forbidden from pushing directly to `main` or rewriting history via `--force`.
2. **Mandatory Reviews:** All AI contributions must arrive as a Pull Request and be explicitly approved by a human designated in the `.github/CODEOWNERS` file.
3. **Secret Scanning:** All commits must pass local `gitleaks` pre-commit checks before being pushed to the remote repository.
4. **No Hook Bypass:** `--no-verify`, force pushes and pushes to `main` are refused for agents by `.claude/hooks/guard.sh` and the `deny` rules in `.claude/settings.json`.
5. **Secret Isolation:** Agents may not read `.env*`, `secrets/`, private keys or age key files. Secrets are committed only as SOPS/age ciphertext.
6. **Configuration is Code:** `CLAUDE.md`, memory, skills, hooks and settings are code-owned and change only through a reviewed pull request (see `docs/ai-governance.md`).

## Reporting a Vulnerability
Do not open a public issue. Report privately through GitHub Security Advisories on this repository, or contact the code owner listed in `.github/CODEOWNERS`.
