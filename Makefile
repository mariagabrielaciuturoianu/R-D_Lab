# Default commands (see CLAUDE.md).
.PHONY: lint test hooks venv pki secrets-init secrets deploy health destroy toolkit queries hunt \
        misp-secrets intel-secret misp-up misp-down intel exposure monitor-up monitor-down alert-demo

PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
SIGMA := $(if $(wildcard .venv/bin/sigma),.venv/bin/sigma,sigma)
# Same minor version as CI; sigma needs compiled PyYAML, which newer Pythons may lack.
BOOTSTRAP_PYTHON := $(or $(shell command -v python3.13),python3)

# sops on macOS looks in ~/Library/Application Support by default; use the documented
# location unless the caller already set one. The key itself never enters the repo (R-02).
export SOPS_AGE_KEY_FILE ?= $(HOME)/.config/sops/age/keys.txt

# Non-secret settings, an optional local override, then the decrypted secret (R-02, R-07).
ENV_FILES := --env-file config/stack.env $(if $(wildcard .env),--env-file .env) \
             $(if $(wildcard .runtime/.env.secrets),--env-file .runtime/.env.secrets)
# Compose files live in deploy/; --project-directory keeps their ./ paths repo-relative.
COMPOSE := docker compose --project-directory . -f deploy/compose.yaml $(ENV_FILES)
MISP_COMPOSE := docker compose --project-directory . -f deploy/compose.misp.yaml --env-file config/stack.env \
                $(if $(wildcard .runtime/.env.misp),--env-file .runtime/.env.misp)

# Install the pre-commit hooks into this clone (R-01, R-02).
hooks:
	pre-commit install

# Local virtualenv with pinned test dependencies.
venv:
	$(BOOTSTRAP_PYTHON) -m venv .venv && .venv/bin/pip install -r requirements/dev.txt -r requirements/intel.txt

# gitleaks, no-commit-to-branch and file hygiene on every file (R-01, R-02).
lint:
	pre-commit run --all-files

# Unit tests: guard hook, policies, and every hunt against its samples (R-01..R-17).
test:
	$(PYTHON) -m pytest -v tests/

# Reconvert every Sigma rule to the committed OpenSearch query DSL (R-09).
queries:
	@mkdir -p detections/opensearch
	@for rule in detections/sigma/*.yml; do \
	  out=detections/opensearch/$$(basename $$rule .yml).json; \
	  $(SIGMA) convert -t opensearch_lucene --without-pipeline -f dsl_lucene $$rule 2>/dev/null \
	    | python3 -m json.tool > $$out && echo "wrote $$out"; \
	done

# Load the hunt samples into the running stack and run every committed query (R-10).
hunt:
	$(PYTHON) scripts/run_hunts.py

# Hunt toolkit image (sigma-cli + PyMISP), the same build CI scans and signs (R-17).
toolkit:
	docker build -t hunt-toolkit:local toolkit/

# Local root CA and leaf certificates for mTLS; keeps existing ones (R-07).
pki:
	./scripts/pki.sh certs

# Create the SOPS/age-encrypted admin and Dashboards passwords, interactively (R-02).
secrets-init:
	./scripts/new-secret.sh

# Decrypt into .runtime/ for this deployment only (R-02).
secrets:
	./scripts/render-runtime.sh

# Idempotent: safe to run again on a running stack (R-07).
deploy: pki secrets
	$(MAKE) --no-print-directory up

up:
	$(COMPOSE) up -d --wait --wait-timeout 180 opensearch
	$(COMPOSE) up -d dashboards
	@echo "OpenSearch is up; run make health. Dashboards: https://localhost (DASHBOARDS_PORT)"

health:
	./scripts/health.sh

# Removes containers, network, data volume and every decrypted file (R-02).
destroy:
	-$(COMPOSE) --profile monitoring down -v --remove-orphans
	rm -f .runtime/.env.secrets .runtime/internal_users.yml

# --- Threat intelligence (Lab 6) -------------------------------------------------------
# Random MISP passwords and admin API key, straight into SOPS ciphertext (R-02).
misp-secrets:
	./scripts/new-misp-secret.sh

# Shodan API key, typed once without echo, stored as SOPS ciphertext (R-02, R-12).
intel-secret:
	./scripts/new-intel-secret.sh

# MISP on https://localhost:$MISP_HTTPS_PORT; the first boot takes several minutes (R-11).
misp-up: pki
	./scripts/render-misp-runtime.sh
	$(MAKE) --no-print-directory misp-start

misp-start:
	$(MISP_COMPOSE) up -d --wait --wait-timeout 1200

misp-down:
	-$(MISP_COMPOSE) down -v --remove-orphans
	rm -f .runtime/.env.misp

# Seed the campaign event, pull indicators, enrich telemetry, reorder hunts (R-08, R-11).
intel:
	$(PYTHON) scripts/intel.py

# Outside-in view of the project's own public IP via Shodan (R-12).
exposure:
	./scripts/render-misp-runtime.sh
	$(PYTHON) scripts/exposure_check.py

# --- Monitoring (Lab 7) ------------------------------------------------------------------
# Prometheus, Alertmanager and the blackbox prober, every link mTLS from the root CA (R-18).
monitor-up: pki
	$(COMPOSE) --profile monitoring up -d --wait prometheus alertmanager blackbox
	@echo "Prometheus https://localhost:9090  Alertmanager https://localhost:9093"

monitor-down:
	-$(COMPOSE) --profile monitoring rm -sf prometheus alertmanager blackbox

# Stop OpenSearch, watch SocServiceDown fire in Alertmanager, start it, watch it resolve.
alert-demo:
	./scripts/alert_demo.sh
