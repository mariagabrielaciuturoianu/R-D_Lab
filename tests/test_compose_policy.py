"""Policy tests for compose.yaml (R-07): pinned arm64 images, loopback-only ports, mTLS config."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE = (ROOT / "compose.yaml").read_text()
OPENSEARCH = (ROOT / "config" / "opensearch.yml").read_text()
DASHBOARDS = (ROOT / "config" / "opensearch_dashboards.yml").read_text()


def test_every_image_is_pinned_by_digest():
    images = re.findall(r"^\s*image:\s*(\S+)", COMPOSE, re.M)
    assert images, "no images found"
    for image in images:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), f"unpinned image: {image}"


def test_every_service_targets_arm64():
    services = len(re.findall(r"^\s*image:", COMPOSE, re.M))
    assert len(re.findall(r"^\s*platform:\s*linux/arm64\s*$", COMPOSE, re.M)) == services


def test_host_ports_bind_loopback_from_variables():
    ports = re.findall(r'^\s*-\s*"([^"]*:\d+)"\s*$', COMPOSE, re.M)
    assert ports, "no published ports found"
    for port in ports:
        assert re.fullmatch(r"127\.0\.0\.1:\$\{[A-Z_]+\}:\d+", port), f"bad port binding: {port}"


def test_no_plaintext_password_in_compose():
    values = re.findall(r"^\s*[A-Z_]*PASSWORD[A-Z_]*:\s*(.+)$", COMPOSE, re.M)
    for value in values:
        assert re.fullmatch(r'"?\$\{[A-Z_]+(:-)?\}"?', value.strip()), f"literal password: {value}"


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
