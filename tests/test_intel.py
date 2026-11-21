"""Feed lifecycle, enrichment outcome and hunt prioritisation (R-08, R-11). No MISP needed."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("intel_lib", ROOT / "scripts/intel_lib.py")
intel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(intel)

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
VOLT = 'misp-galaxy:threat-actor="Volt Typhoon"'
SANDWORM = 'misp-galaxy:threat-actor="Sandworm Team"'


def attr(value, to_ids=True, days_old=1, event_id="1", info="campaign", tags=(VOLT,)):
    return {"value": value, "to_ids": to_ids, "timestamp": NOW - timedelta(days=days_old),
            "event_id": event_id, "event_info": info, "tags": list(tags)}


def test_lifecycle_keeps_only_trusted_fresh_valid_ips():
    lookup = intel.build_lookup([
        attr("203.0.113.66"),
        attr("192.0.2.10", to_ids=False),     # context only: not for detection
        attr("198.51.100.99", days_old=45),   # aged out
        attr("not-an-ip"),                    # malformed value
    ], now=NOW)
    assert list(lookup) == ["203.0.113.66"]


def test_lifecycle_deduplicates_and_merges_events_and_actors():
    lookup = intel.build_lookup([
        attr("203.0.113.66", event_id="1", info="first report"),
        attr("203.0.113.66", event_id="2", info="follow-up", tags=(SANDWORM,)),
    ], now=NOW)
    entry = lookup["203.0.113.66"]
    assert [e["id"] for e in entry["events"]] == ["1", "2"]
    assert entry["actors"] == ["Sandworm Team", "Volt Typhoon"]


def test_lookup_is_sorted_for_small_diffs():
    lookup = intel.build_lookup([attr("203.0.113.66"), attr("198.51.100.23")], now=NOW)
    assert list(lookup) == sorted(lookup)


def test_enrichment_changes_the_outcome_only_for_a_known_bad_ip():
    lookup = intel.build_lookup([attr("203.0.113.66")], now=NOW)
    bad = intel.enrich({"destination": {"ip": "203.0.113.66"}, "event": {"code": "3"}}, lookup)
    clean = intel.enrich({"destination": {"ip": "198.18.0.20"}, "event": {"code": "3"}}, lookup)
    assert bad["threat"]["indicator"]["matched"] is True
    assert bad["threat"]["indicator"]["actors"] == ["Volt Typhoon"]
    assert bad["event"]["risk_score"] == intel.MATCH_RISK
    assert "threat.indicator.matched" in bad["tags"]
    assert "threat" not in clean and "tags" not in clean
    assert clean["event"]["risk_score"] == intel.BASE_RISK


def test_active_campaign_moves_matching_hunts_up_the_queue():
    hunts = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "hunts").glob("H-*.yaml"))]
    quiet = [q["id"] for q in intel.prioritise(hunts, [])]
    active = intel.prioritise(hunts, ["Sandworm Team"])
    assert quiet == ["H-003", "H-001", "H-002"]              # base priorities 2, 3, 4
    assert [q["id"] for q in active] == ["H-001", "H-003", "H-002"]
    h001 = next(q for q in active if q["id"] == "H-001")
    assert h001["effective_priority"] == 1 and h001["active_actors"] == ["Sandworm Team"]


def test_public_ip_is_masked():
    assert intel.mask_ip("81.196.12.34") == "81.196.x.x"


def test_new_open_port_raises_an_exposure_alert():
    assert intel.exposure_change([443], [443]) == {"new": [], "closed": [], "alert": False}
    assert intel.exposure_change([443], [443, 8443]) == {"new": [8443], "closed": [], "alert": True}
    assert intel.exposure_change(None, []) == {"new": [], "closed": [], "alert": False}


def test_network_samples_cover_every_lifecycle_outcome():
    lines = (ROOT / "tests/samples/intel/network.ndjson").read_text().splitlines()
    expected = {json.loads(line)["intel"]["expected"] for line in lines if line.strip()}
    assert expected == {"flagged", "warninglisted", "not-for-detection", "unknown"}
