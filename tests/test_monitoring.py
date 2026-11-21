"""Monitoring configuration (R-18): mTLS between Prometheus, Alertmanager and the prober."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_monitoring_links_are_tls_with_client_certificates():
    prom = (ROOT / "config/prometheus/prometheus.yml").read_text()
    assert prom.count("scheme: https") == 3
    assert "cert_file: /certs/prometheus.pem" in prom
    assert "RequireAndVerifyClientCert" in (ROOT / "config/blackbox/web.yml").read_text()
    probe = (ROOT / "config/blackbox/blackbox.yml").read_text()
    assert "cert_file: /certs/monitor.pem" in probe and "valid_status_codes: [200, 401]" in probe


def test_availability_alert_exists():
    alerts = (ROOT / "config/prometheus/alerts.yml").read_text()
    assert "alert: SocServiceDown" in alerts and "probe_success" in alerts
