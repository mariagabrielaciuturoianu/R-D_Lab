#!/usr/bin/env python3
"""Load the hunt samples into the running stack and run every committed hunt query (R-10).

Applies config/opensearch/hunt-telemetry-template.json, rebuilds the hunt-telemetry-lab
index from tests/samples/hunts/, then runs each hunt's committed OpenSearch query and
checks it. A hunt fails if it misses one of its own positives or hits any negative sample
(near misses included). A hit on another hunt's positive is reported as overlap, not a
failure: attack chains share events (PowerShell launched through WMI is both H-001 and
H-002). Exit code 1 if any hunt fails.
"""
import json
import sys

import yaml

from stack_client import ROOT, OpenSearch

INDEX = "hunt-telemetry-lab"

os_ = OpenSearch()
hunts = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "hunts").glob("H-*.yaml"))]

docs, expected = [], {}
for h in hunts:
    for kind in ("positive", "negative"):
        for line in (ROOT / h["samples"][kind]).read_text().splitlines():
            if line.strip():
                doc = json.loads(line)
                doc["hunt"].update({"id": h["id"], "expected": kind})
                docs.append(doc)
    expected[h["id"]] = sum(1 for d in docs if d["hunt"]["id"] == h["id"] and d["hunt"]["expected"] == "positive")
total = os_.reload_index(INDEX, "hunt-telemetry", ROOT / "config/opensearch/hunt-telemetry-template.json", docs)
print(f"Loaded {total} sample events into {INDEX} (positives and near-miss negatives for {len(hunts)} hunts)\n")

failed = False
for h in hunts:
    query = json.loads((ROOT / h["query"]).read_text())
    query["size"] = 50
    hits = os_.call("POST", f"/{INDEX}/_search", query)["hits"]["hits"]
    tag = lambda x: (x["_source"]["hunt"]["id"], x["_source"]["hunt"]["expected"])
    own_pos = [x for x in hits if tag(x) == (h["id"], "positive")]
    negatives = [x for x in hits if tag(x)[1] == "negative"]
    overlap = [x for x in hits if tag(x)[1] == "positive" and tag(x)[0] != h["id"]]
    ok = len(own_pos) == expected[h["id"]] and not negatives
    failed |= not ok
    print(f"{'PASS' if ok else 'FAIL'}  {h['id']}  {h['title']}  ({', '.join(h['techniques'])})")
    print(f"      {len(own_pos)}/{expected[h['id']]} own positives, {len(negatives)} negatives hit, "
          f"{len(overlap)} overlap with other hunts")
    for x in hits:
        s = x["_source"]
        kind = "overlap" if x in overlap else s["hunt"]["expected"]
        print(f"        - [{s['hunt']['id']} {kind}] {s['host']['name']}: "
              f"{s['process']['parent']['name']} -> {s['process']['command_line'][:70]}")
    print()
sys.exit(1 if failed else 0)
