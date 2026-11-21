#!/usr/bin/env python3
"""MISP to SOC: seed, pull, enrich, prioritise (R-08, R-11).

1. Seed (once): an exercise campaign event in MISP, attributed with galaxy tags, holding
   documentation-range IPs (RFC 5737) so no real third party is ever named. It contains a
   trusted C2 relay and staging server, a context-only address (to_ids false), and a public
   resolver flagged to_ids on purpose, which MISP's warninglist must remove. A follow-up
   event repeats the relay so deduplication has something to merge.
2. Pull: attributes flagged to_ids, warninglists enforced by MISP, seen within MAX_AGE days,
   deduplicated (scripts/intel_lib.py). Written to enrich/ (git-ignored: live intelligence
   is never committed).
3. Enrich: network telemetry is tagged threat.indicator.matched and its risk score raised
   when it touches a pulled IP; everything else is untouched. Loaded into OpenSearch.
4. Prioritise: hunts whose threat actors appear in current MISP data move up the queue.
Every network sample declares its expected outcome; exit code 1 if reality differs.
"""
import json
import sys
from datetime import timezone

import urllib3
import yaml
from pymisp import MISPEvent, PyMISP

import intel_lib
from stack_client import CA, ROOT, OpenSearch, runtime, settings

MAX_AGE_DAYS = 30
INDEX = "intel-telemetry-lab"
SANDWORM = 'misp-galaxy:threat-actor="Sandworm Team"'
SEED = [
    {
        "info": "RDLab exercise: Sandworm-style intrusion into an ICS network (documentation IPs)",
        "tags": ["tlp:clear", SANDWORM,
                 'misp-galaxy:mitre-attack-pattern="Windows Management Instrumentation - T1047"',
                 'misp-galaxy:mitre-attack-pattern="OS Credential Dumping: NTDS - T1003.003"'],
        "attributes": [
            ("203.0.113.66", True, "C2 relay on a compromised SOHO router"),
            ("198.51.100.23", True, "Staging server for tooling"),
            ("192.0.2.10", False, "Shared hosting seen in passing: context only, not for detection"),
            ("8.8.8.8", True, "Public resolver flagged on purpose: the warninglist must drop it"),
        ],
    },
    {
        "info": "RDLab exercise: follow-up report on shared Sandworm infrastructure",
        "tags": ["tlp:clear", SANDWORM],
        "attributes": [("203.0.113.66", True, "Same relay reused in a second intrusion")],
    },
]


def misp_client():
    key = runtime(".env.misp", "make misp-up")["MISP_ADMIN_KEY"]
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # never triggered: ssl=CA
    return PyMISP(f"https://localhost:{settings()['MISP_HTTPS_PORT']}", key, ssl=str(CA))


def seed(misp):
    existing = {e["Event"]["info"] for e in misp.search(controller="events", eventinfo="RDLab exercise%",
                                                         metadata=True)}
    for spec in SEED:
        if spec["info"] in existing:
            continue
        ev = MISPEvent()
        ev.info, ev.distribution, ev.threat_level_id, ev.analysis = spec["info"], 0, 1, 2
        for tag in spec["tags"]:
            ev.add_tag(tag)
        for value, to_ids, comment in spec["attributes"]:
            ev.add_attribute("ip-dst", value, to_ids=to_ids, comment=comment)
        created = misp.add_event(ev, pythonify=True)
        print(f"seeded MISP event {created.id}: {spec['info']}")


def enable_warninglists(misp):
    misp.update_warninglists()
    misp.toggle_warninglist(warninglist_name="List of known IPv4 public DNS resolvers", force_enable=True)


def as_dict(a):
    return {"value": a.value, "to_ids": bool(a.to_ids), "timestamp": a.timestamp.astimezone(timezone.utc),
            "event_id": str(a.event_id), "event_info": a.Event.info if hasattr(a, "Event") else "",
            "tags": [t.name for t in getattr(a, "tags", [])]}


def pull(misp):
    common = {"controller": "attributes", "type_attribute": ["ip-dst", "ip-src"],
              "eventinfo": "RDLab exercise%", "include_event_tags": True, "pythonify": True}
    raw = [as_dict(a) for a in misp.search(**common)]
    kept = [as_dict(a) for a in misp.search(**common, to_ids=True, enforce_warninglist=True,
                                            timestamp=f"{MAX_AGE_DAYS}d")]
    lookup = intel_lib.build_lookup(kept, max_age_days=MAX_AGE_DAYS)
    print(f"\nFeed lifecycle: {len(raw)} IP attributes in MISP -> {len(lookup)} indicators kept")
    for a in sorted(raw, key=lambda r: (r["value"], r["event_id"])):
        if a["value"] in lookup:
            verdict = "kept"
        elif not a["to_ids"]:
            verdict = "dropped: to_ids false (context only)"
        else:
            verdict = "dropped: MISP warninglist"
        print(f"  {a['value']:<15} event {a['event_id']:<4} {verdict}")
    for ip, entry in lookup.items():
        if len(entry["events"]) > 1:
            print(f"  {ip} deduplicated across events {', '.join(e['id'] for e in entry['events'])}")
    return lookup


def main():
    misp = misp_client()
    enable_warninglists(misp)
    seed(misp)
    lookup = pull(misp)
    if not lookup:
        sys.exit("MISP returned no indicators; the previous lookup stays in place.")
    out = ROOT / "enrich"
    out.mkdir(exist_ok=True)
    (out / "ioc_ip.json.tmp").write_text(json.dumps(lookup, indent=2) + "\n")
    (out / "ioc_ip.json.tmp").replace(out / "ioc_ip.json")  # atomic: readers never see half a file

    events = [json.loads(line) for line in (ROOT / "tests/samples/intel/network.ndjson").read_text().splitlines()
              if line.strip()]
    enriched = [intel_lib.enrich(e, lookup) for e in events]
    count = OpenSearch().reload_index(INDEX, "intel-telemetry",
                                      ROOT / "config/opensearch/intel-telemetry-template.json", enriched)
    print(f"\nEnrichment: {count} network events loaded into {INDEX}")
    wrong = 0
    for e in enriched:
        flagged = e.get("threat", {}).get("indicator", {}).get("matched", False)
        ok = flagged == (e["intel"]["expected"] == "flagged")
        wrong += not ok
        actors = ", ".join(e["threat"]["indicator"]["actors"]) if flagged else "-"
        print(f"  {'OK ' if ok else 'BAD'} {e['host']['name']:<9} -> {e['destination']['ip']:<15} "
              f"risk {e['event']['risk_score']:>3}  matched={str(flagged):<5} actors={actors:<14} "
              f"({e['intel']['expected']})")

    hunts = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "hunts").glob("H-*.yaml"))]
    active = sorted({a for entry in lookup.values() for a in entry["actors"]})
    before = intel_lib.prioritise(hunts, [])
    after = intel_lib.prioritise(hunts, active)
    (out / "hunt_queue.json").write_text(json.dumps(after, indent=2) + "\n")
    print(f"\nHunt queue (active in MISP: {', '.join(active) or 'none'})")
    print(f"  without intelligence: {' > '.join(q['id'] for q in before)}")
    print(f"  with MISP:            {' > '.join(q['id'] for q in after)}")
    for q in after:
        why = f"raised by {', '.join(q['active_actors'])}" if q["active_actors"] else "no active actor"
        print(f"    {q['id']} priority {q['base_priority']} -> {q['effective_priority']}  ({why})  {q['title']}")
    sys.exit(1 if wrong else 0)


if __name__ == "__main__":
    main()
