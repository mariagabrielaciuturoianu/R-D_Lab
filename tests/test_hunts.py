"""Hunts as code (R-08, R-09, R-10, R-13).

Every hunt in hunts/ must name its hypothesis, ATT&CK techniques and threat actors, point
at a Sigma rule that carries the same techniques, fire on every positive sample, stay
quiet on every negative sample (near misses included), and ship a committed OpenSearch
query that still equals the conversion of its rule. A rule weakened by a careless or
LLM-drafted edit fails here before it can merge.
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from sigma_match import rule_matches

ROOT = Path(__file__).resolve().parent.parent
HUNTS = sorted((ROOT / "hunts").glob("H-*.yaml"))
REQUIRED = {"id", "title", "hypothesis", "threat_actors", "techniques", "data_sources",
            "rule", "query", "samples", "confirms", "refutes", "base_priority"}
# sigma-cli next to the running interpreter (a venv), else on PATH (CI).
_venv_sigma = Path(sys.executable).with_name("sigma")
SIGMA = str(_venv_sigma) if _venv_sigma.exists() else shutil.which("sigma")


def hunt(path):
    return yaml.safe_load(path.read_text())


def events(rel):
    lines = (ROOT / rel).read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_there_are_hunts():
    assert len(HUNTS) >= 3


@pytest.mark.parametrize("path", HUNTS, ids=lambda p: p.stem)
def test_hunt_is_complete(path):
    h = hunt(path)
    assert REQUIRED <= h.keys(), f"missing: {REQUIRED - h.keys()}"
    assert h["id"] == path.stem
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in h["techniques"])
    assert all(re.fullmatch(r"G\d{4}", a["mitre_group"]) for a in h["threat_actors"])
    assert 1 <= h["base_priority"] <= 5
    for rel in (h["rule"], h["query"], h["samples"]["positive"], h["samples"]["negative"]):
        assert (ROOT / rel).is_file(), f"{rel} does not exist"


@pytest.mark.parametrize("path", HUNTS, ids=lambda p: p.stem)
def test_rule_carries_the_hunt_techniques(path):
    h = hunt(path)
    tags = yaml.safe_load((ROOT / h["rule"]).read_text())["tags"]
    for t in h["techniques"]:
        assert f"attack.{t.lower()}" in tags, f"{h['rule']} lacks attack.{t.lower()}"


@pytest.mark.parametrize("path", HUNTS, ids=lambda p: p.stem)
def test_rule_fires_on_every_positive_sample(path):
    h = hunt(path)
    samples = events(h["samples"]["positive"])
    assert samples
    missed = [e["hunt"]["sample"] for e in samples if not rule_matches(ROOT / h["rule"], e)]
    assert not missed, f"blind to: {missed}"


@pytest.mark.parametrize("path", HUNTS, ids=lambda p: p.stem)
def test_rule_stays_quiet_on_every_negative_sample(path):
    h = hunt(path)
    samples = events(h["samples"]["negative"])
    assert len(samples) >= 2, "need at least two negatives, one of them a near miss"
    noisy = [e["hunt"]["sample"] for e in samples if rule_matches(ROOT / h["rule"], e)]
    assert not noisy, f"false positives: {noisy}"


@pytest.mark.skipif(not SIGMA, reason="sigma-cli not installed")
@pytest.mark.parametrize("path", HUNTS, ids=lambda p: p.stem)
def test_committed_query_matches_its_rule(path):
    h = hunt(path)
    out = subprocess.run(
        [SIGMA, "convert", "-t", "opensearch_lucene", "--without-pipeline",
         "-f", "dsl_lucene", str(ROOT / h["rule"])],
        capture_output=True, text=True, check=True,
    ).stdout
    assert json.loads(out) == json.loads((ROOT / h["query"]).read_text()), "reconvert: make queries"


@pytest.mark.skipif(not SIGMA, reason="sigma-cli not installed")
def test_rules_pass_sigma_validation():
    run = subprocess.run([SIGMA, "check", "--fail-on-issues", str(ROOT / "detections/sigma")],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout[-2000:]
