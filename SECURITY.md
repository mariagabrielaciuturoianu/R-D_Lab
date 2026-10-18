# Security Policy

## Supported Versions
Only the latest commit on the `main` branch is actively supported and evaluated for security updates.

## AI Agent Contribution Policy
To mitigate operational and internal risks, all code generated or committed by AI agents (e.g., Claude Code, Gemini CLI) MUST adhere to the following strict controls:
1. **No Direct Pushes:** AI agents operate with restricted credentials and are forbidden from pushing directly to `main` or rewriting history via `--force`.
2. **Mandatory Reviews:** All AI contributions must arrive as a Pull Request and be explicitly approved by a human designated in the `CODEOWNERS` file.
3. **Secret Scanning:** All commits must pass local `gitleaks` pre-commit checks before being pushed to the remote repository.
