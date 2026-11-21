"""Policy tests for every compose file (R-07, R-11): pinned arm64 images, loopback-only
ports, no literal secrets; plus the mTLS settings of the SOC stack."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILES = sorted((ROOT / "deploy").glob("compose*.yaml"))
COMPOSE = (ROOT / "deploy" / "compose.yaml").read_text()
OPENSEARCH = (ROOT / "config" / "opensearch.yml").read_text()
DASHBOARDS = (ROOT / "config" / "opensearch_dashboards.yml").read_text()
each_compose = pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)


def test_both_stacks_are_covered():
    assert {p.name for p in COMPOSE_FILES} >= {"compose.yaml", "compose.misp.yaml"}


@each_compose
def test_every_image_is_pinned_by_digest(path):
    images = re.findall(r"^\s*image:\s*(\S+)", path.read_text(), re.M)
    assert images, "no images found"
    for image in images:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"unpinned image: {image}"


@each_compose
def test_every_service_targets_arm64(path):
    text = path.read_text()
    services = len(re.findall(r"^\s*image:", text, re.M))
    assert len(re.findall(r"^\s*platform:\s*linux/arm64\s*$", text, re.M)) == services


@each_compose
def test_host_ports_bind_loopback_from_variables(path):
    ports = re.findall(r'^\s*-\s*"([^"]*:\d+)"\s*$', path.read_text(), re.M)
    assert ports, "no published ports found"
    for port in ports:
        assert re.fullmatch(r"127\.0\.0\.1:\$\{[A-Z_]+\}:\d+", port), f"bad port binding: {port}"


@each_compose
def test_no_plaintext_password_in_compose(path):
    values = re.findall(r"^\s*[A-Z_]*(?:PASSWORD|_KEY)[A-Z_]*:\s*(.+)$", path.read_text(), re.M)
    for value in values:
        assert re.fullmatch(r'"?\$\{[A-Z_]+(:-)?\}"?', value.strip()), f"literal secret: {value}"


def test_opensearch_requires_client_certificates():
    assert re.search(r"^plugins\.security\.ssl\.http\.enabled:\s*true", OPENSEARCH, re.M)
    assert re.search(r"^plugins\.security\.ssl\.http\.clientauth_mode:\s*REQUIRE", OPENSEARCH, re.M)
    settings = [line for line in OPENSEARCH.splitlines() if not line.lstrip().startswith("#")]
    assert not any("demo" in line.lower() for line in settings), "demo security config in use"
    assert re.search(r'DISABLE_INSTALL_DEMO_CONFIG:\s*"true"', COMPOSE)


def test_dashboards_verifies_server_and_presents_client_cert():
    assert re.search(r"^opensearch\.ssl\.verificationMode:\s*full", DASHBOARDS, re.M)
    assert re.search(r"^opensearch\.ssl\.alwaysPresentCertificate:\s*true", DASHBOARDS, re.M)
    assert re.search(r"^server\.ssl\.enabled:\s*true", DASHBOARDS, re.M)
