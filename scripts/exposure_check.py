#!/usr/bin/env python3
"""Outside-in exposure check of the project's own public IP with Shodan (R-12).

Rules of engagement: only the address this machine is using right now is queried, as
reported by Shodan itself, so no third-party address can be looked up by mistake. The
public IP is personal data: it is masked in all output, and the full snapshot is kept in
exposure/ (git-ignored). A port open now but not in the previous snapshot raises an alert.
The API key comes from .runtime/ (make intel-secret, make misp-up) and is never printed.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import intel_lib
from stack_client import ROOT, runtime

API = "https://api.shodan.io"


def shodan(path, key):
    url = f"{API}{path}?{urllib.parse.urlencode({'key': key})}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None  # Shodan has no record of this address
        sys.exit(f"Shodan {path.split('/')[1]} request failed: HTTP {err.code}")


def main():
    key = runtime(".env.misp", "make intel-secret, then make exposure").get("SHODAN_KEY")
    if not key:
        sys.exit("No SHODAN_KEY in .runtime/.env.misp: run make intel-secret, then make exposure.")
    plan = shodan("/api-info", key) or {}
    ip = shodan("/tools/myip", key)
    host = shodan(f"/shodan/host/{ip}", key)
    ports = sorted(host.get("ports", [])) if host else []
    services = sorted({(s.get("port"), s.get("transport", "tcp"), (s.get("product") or s.get("_shodan", {}).get("module", "?")))
                       for s in (host or {}).get("data", [])})

    out = ROOT / "exposure"
    out.mkdir(exist_ok=True)
    latest, previous = out / "latest.json", out / "previous.json"
    prev_ports = json.loads(latest.read_text())["ports"] if latest.exists() else None
    if latest.exists():
        latest.replace(previous)
    snapshot = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ip": ip, "indexed": host is not None, "ports": ports,
                "last_update": (host or {}).get("last_update")}
    latest.write_text(json.dumps(snapshot, indent=2) + "\n")
    change = intel_lib.exposure_change(prev_ports, ports)

    print(f"Shodan plan: {plan.get('plan', '?')}, query credits left: {plan.get('query_credits', '?')}")
    print(f"Own public IP (masked): {intel_lib.mask_ip(ip)}")
    if host is None:
        print("Shodan has no record of this address: nothing exposed has been indexed.")
    else:
        print(f"Indexed by Shodan, last crawl {snapshot['last_update']}: open ports {ports or 'none'}")
        for port, transport, product in services:
            print(f"  {port}/{transport}  {product}")
    if prev_ports is None:
        print("First snapshot recorded; later runs alert on any newly exposed port.")
    else:
        print(f"Change since previous snapshot: new {change['new'] or 'none'}, closed {change['closed'] or 'none'}")
    if change["alert"]:
        print("ALERT: a new port is exposed to the internet (R-12)")
        sys.exit(2)


if __name__ == "__main__":
    main()
