# Default commands (see CLAUDE.md). deploy/destroy are added with the stack in Lab 3.
.PHONY: lint test hooks

# Install the pre-commit hooks into this clone (R-01, R-02).
hooks:
	pre-commit install

# gitleaks, no-commit-to-branch and file hygiene on every file (R-01, R-02).
lint:
	pre-commit run --all-files

# Unit tests; tests/ arrives with the project components.
test:
	@if [ -d tests ]; then python3 -m pytest tests/; else echo "no tests yet"; fi
