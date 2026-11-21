#!/usr/bin/env python3
"""Outside-in exposure check of the project's own public IP with Shodan (R-12).

Rules of engagement: only the address this machine is using right now is queried, as
reported by Shodan itself, so no third-party address can be looked up by mistake. The
public IP is personal data: it is masked in all output, and the full snapshot is kept in
exposure/ (git-ignored). A port open now but not in the previous snapshot raises an alert.
The API key comes from .runtime/ (make intel-secret, make misp-up) and is never printed.

Free Shodan accounts may not call the host API (HTTP 403). The check then falls back to
Shodan InternetDB, the free per-IP view of the same scan data (ports, hostnames, tags,
known CVEs), and records which source answered.
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
INTERNETDB = "https://internetdb.shodan.io"
# InternetDB's CDN rejects Python's default User-Agent with 403; identify the tool honestly.
HEADERS = {"User-Agent": "rdlab-exposure-check/1.0 (+https://github.com/mariagabrielaciuturoianu/R-D_Lab)"}


class Forbidden(Exception):
    pass


def get(url, label):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None  # no record of this address
        if err.code == 403:
            raise Forbidden(label) from None
        sys.exit(f"{label} request failed: HTTP {err.code}")


def shodan(path, key):
    return get(f"{API}{path}?{urllib.parse.urlencode({'key': key})}", f"Shodan {path.rsplit('/', 1)[0] or path}")


def lookup(ip, key):
    """(source, ports, services, last_update, indexed) from the host API, else InternetDB."""
    try:
        host = shodan(f"/shodan/host/{ip}", key)
        services = sorted({(s.get("port"), s.get("transport", "tcp"),
                            s.get("product") or s.get("_shodan", {}).get("module", "?"))
                           for s in (host or {}).get("data", [])})
        return ("Shodan host API", sorted((host or {}).get("ports", [])), services,
                (host or {}).get("last_update"), host is not None)
    except Forbidden:
        db = get(f"{INTERNETDB}/{ip}", "Shodan InternetDB")
        ports = sorted((db or {}).get("ports", []))
        extra = [f"tags {', '.join(db['tags'])}"] if db and db.get("tags") else []
        extra += [f"known CVEs {len(db['vulns'])}"] if db and db.get("vulns") else []
        services = [(p, "tcp", "; ".join(extra) or "-") for p in ports]
        return ("Shodan InternetDB (host API needs a paid plan)", ports, services, None, db is not None)


def main():
    key = runtime(".env.misp", "make intel-secret, then make exposure").get("SHODAN_KEY")
    if not key:
        sys.exit("No SHODAN_KEY in .runtime/.env.misp: run make intel-secret, then make exposure.")
    plan = shodan("/api-info", key) or {}
    ip = shodan("/tools/myip", key)
    source, ports, services, last_update, indexed = lookup(ip, key)

    out = ROOT / "exposure"
    out.mkdir(exist_ok=True)
    latest, previous = out / "latest.json", out / "previous.json"
    prev_ports = json.loads(latest.read_text())["ports"] if latest.exists() else None
    if latest.exists():
        latest.replace(previous)
    snapshot = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ip": ip, "source": source, "indexed": indexed, "ports": ports,
                "last_update": last_update}
    latest.write_text(json.dumps(snapshot, indent=2) + "\n")
    change = intel_lib.exposure_change(prev_ports, ports)

    print(f"Shodan plan: {plan.get('plan', '?')}, query credits left: {plan.get('query_credits', '?')}")
    print(f"Source: {source}")
    print(f"Own public IP (masked): {intel_lib.mask_ip(ip)}")
    if not indexed:
        print("Shodan has no record of this address: nothing exposed has been indexed.")
    else:
        crawl = f", last crawl {last_update}" if last_update else ""
        print(f"Indexed by Shodan{crawl}: open ports {ports or 'none'}")
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
