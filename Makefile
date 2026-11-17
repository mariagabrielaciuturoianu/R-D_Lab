# Default commands (see CLAUDE.md). deploy/destroy are added with the stack in Lab 3.
.PHONY: lint test hooks venv

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

# Install the pre-commit hooks into this clone (R-01, R-02).
hooks:
	pre-commit install

# Local virtualenv with pinned test dependencies.
venv:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

# gitleaks, no-commit-to-branch and file hygiene on every file (R-01, R-02).
lint:
	pre-commit run --all-files

# Unit tests, including the guard hook regression suite (R-01..R-06).
test:
	$(PYTHON) -m pytest -v tests/
