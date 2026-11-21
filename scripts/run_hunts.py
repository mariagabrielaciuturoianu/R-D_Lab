#!/usr/bin/env python3
"""Load the hunt samples into the running stack and run every committed hunt query (R-10).

Applies config/opensearch/hunt-telemetry-template.json, rebuilds the hunt-telemetry-lab
index from tests/samples/hunts/, then runs each hunt's committed OpenSearch query and
checks it. A hunt fails if it misses one of its own positives or hits any negative sample
(near misses included). A hit on another hunt's positive is reported as overlap, not a
failure: attack chains share events (PowerShell launched through WMI is both H-001 and
H-002). Talks to OpenSearch over mTLS with the admin client certificate; the password
comes from .runtime/ (make deploy). Exit code 1 if any hunt fails.
"""
import base64
import json
import ssl
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
INDEX = "hunt-telemetry-lab"


def env_file(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


settings = env_file(ROOT / "config/stack.env")
if (ROOT / ".env").exists():
    settings.update(env_file(ROOT / ".env"))
runtime = ROOT / ".runtime/.env.secrets"
if not runtime.exists():
    sys.exit("No decrypted secret in .runtime/: run make deploy first.")
password = env_file(runtime)["OPENSEARCH_ADMIN_PASSWORD"]

ctx = ssl.create_default_context(cafile=str(ROOT / "certs/root-ca.pem"))
ctx.load_cert_chain(ROOT / "certs/admin.pem", ROOT / "certs/admin-key.pem")
BASE = f"https://localhost:{settings['OPENSEARCH_PORT']}"
AUTH = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()


def call(method, path, body=None, ndjson=False):
    data = None
    if body is not None:
        data = body.encode() if ndjson else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={
        "Authorization": AUTH,
        "Content-Type": "application/x-ndjson" if ndjson else "application/json",
    })
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        if method == "DELETE" and err.code == 404:
            return {}
        sys.exit(f"{method} {path}: HTTP {err.code} {err.read().decode()[:300]}")


hunts = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "hunts").glob("H-*.yaml"))]

call("PUT", "/_index_template/hunt-telemetry",
     json.loads((ROOT / "config/opensearch/hunt-telemetry-template.json").read_text()))
call("DELETE", f"/{INDEX}")
bulk, expected = [], {}
for h in hunts:
    for kind in ("positive", "negative"):
        for line in (ROOT / h["samples"][kind]).read_text().splitlines():
            if line.strip():
                doc = json.loads(line)
                doc["hunt"].update({"id": h["id"], "expected": kind})
                bulk += [json.dumps({"index": {"_index": INDEX}}), json.dumps(doc)]
    expected[h["id"]] = sum(1 for line in (ROOT / h["samples"]["positive"]).read_text().splitlines() if line.strip())
result = call("POST", "/_bulk?refresh=true", "\n".join(bulk) + "\n", ndjson=True)
if result.get("errors"):
    sys.exit("bulk load failed: " + json.dumps(result)[:500])
total = call("GET", f"/{INDEX}/_count")["count"]
print(f"Loaded {total} sample events into {INDEX} (positives and near-miss negatives for {len(hunts)} hunts)\n")

failed = False
for h in hunts:
    query = json.loads((ROOT / h["query"]).read_text())
    query["size"] = 50
    hits = call("POST", f"/{INDEX}/_search", query)["hits"]["hits"]
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
