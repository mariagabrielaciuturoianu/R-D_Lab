"""Threat-intelligence decisions, testable without MISP or OpenSearch (R-08, R-11).

build_lookup  feed lifecycle: keep only attributes flagged to_ids (MISP's "use for
              detection" trust flag), drop anything older than max_age_days, deduplicate
              by IP while merging the events and threat actors behind it, sort the result.
              Warninglists (known-benign values such as public resolvers) are applied by
              MISP itself through enforce_warninglist on the search.
enrich        the outcome change: telemetry that touches a lookup IP is tagged
              threat.indicator.matched and its risk score raised; anything else keeps the
              base score and gains nothing.
prioritise    hunts whose threat actors appear in current MISP intelligence move up the
              queue.
"""
import ipaddress
from datetime import datetime, timedelta, timezone

ACTOR_PREFIX = 'misp-galaxy:threat-actor="'
BASE_RISK = 20
MATCH_RISK = 90
ACTIVE_BOOST = 2


def actors_from_tags(tags):
    """Threat-actor names from MISP galaxy tags, e.g. misp-galaxy:threat-actor="Volt Typhoon"."""
    return sorted({t[len(ACTOR_PREFIX):-1] for t in tags if t.startswith(ACTOR_PREFIX) and t.endswith('"')})


def build_lookup(attributes, now=None, max_age_days=30):
    """attributes: dicts with value, to_ids, timestamp (aware datetime), event_id, event_info, tags."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    lookup = {}
    for a in attributes:
        if not a.get("to_ids") or a["timestamp"] < cutoff:
            continue
        try:
            ip = str(ipaddress.ip_address(a["value"]))
        except ValueError:
            continue
        entry = lookup.setdefault(ip, {"events": [], "actors": [], "last_seen": a["timestamp"]})
        if a["event_id"] not in [e["id"] for e in entry["events"]]:
            entry["events"].append({"id": a["event_id"], "info": a["event_info"]})
        entry["actors"] = sorted(set(entry["actors"]) | set(actors_from_tags(a.get("tags", []))))
        entry["last_seen"] = max(entry["last_seen"], a["timestamp"])
    return {ip: {**e, "last_seen": e["last_seen"].isoformat()} for ip, e in sorted(lookup.items())}


def enrich(event, lookup):
    """Return a copy of an ECS event with threat.* and event.risk_score set from the lookup."""
    out = {**event, "event": {**event.get("event", {})}}
    for field in ("destination", "source"):
        ip = event.get(field, {}).get("ip")
        if ip in lookup:
            hit = lookup[ip]
            out["threat"] = {"indicator": {
                "matched": True,
                "ip": ip,
                "field": f"{field}.ip",
                "provider": "misp",
                "actors": hit["actors"],
                "events": [e["id"] for e in hit["events"]],
                "description": "; ".join(e["info"] for e in hit["events"]),
            }}
            out["event"]["risk_score"] = MATCH_RISK
            out["tags"] = sorted(set(event.get("tags", [])) | {"threat.indicator.matched"})
            return out
    out["event"]["risk_score"] = BASE_RISK
    return out


def mask_ip(ip):
    """Public IPs are personal data: keep the first two octets only, e.g. 81.196.x.x."""
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "masked"


def exposure_change(previous_ports, current_ports):
    """New and closed ports between two Shodan snapshots of the same address (R-12)."""
    prev, cur = set(previous_ports or []), set(current_ports or [])
    return {"new": sorted(cur - prev), "closed": sorted(prev - cur), "alert": bool(cur - prev)}


def prioritise(hunts, active_actors):
    """Hunt queue: an actor seen in current intelligence lowers the priority number (1 = first)."""
    active = set(active_actors)
    queue = []
    for h in hunts:
        matched = sorted(a["name"] for a in h["threat_actors"] if a["name"] in active)
        effective = max(1, h["base_priority"] - ACTIVE_BOOST) if matched else h["base_priority"]
        queue.append({"id": h["id"], "title": h["title"], "base_priority": h["base_priority"],
                      "effective_priority": effective, "active_actors": matched})
    return sorted(queue, key=lambda q: (q["effective_priority"], q["base_priority"], q["id"]))
