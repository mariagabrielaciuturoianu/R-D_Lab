"""Evaluate a Sigma rule against ECS events in Python, so CI tests rule logic without
OpenSearch (R-09). The test reads the same YAML that is converted to the OpenSearch
query, so a rule cannot drift away from its test.

Supported: selections as a map (AND of fields) or a list of maps (OR); value lists (OR,
or AND with |all); modifiers contains, startswith, endswith, all, re; conditions with
and, or, not, parentheses, "1 of <prefix>*", "all of <prefix>*", "1 of them". Plain
string comparisons ignore case, matching the lowercase-normalised keyword fields in
config/opensearch/hunt-telemetry-template.json.
"""
import re
from pathlib import Path

import yaml


def _values(event, dotted):
    """All values at a dotted ECS path, descending into lists."""
    nodes = [event]
    for part in dotted.split("."):
        nxt = []
        for node in nodes:
            for item in node if isinstance(node, list) else [node]:
                if isinstance(item, dict) and part in item:
                    nxt.append(item[part])
        nodes = nxt
    flat = []
    for v in nodes:
        flat.extend(v if isinstance(v, list) else [v])
    return [str(v) for v in flat if v is not None]


def _one(have, want, mods):
    if "re" in mods:
        return re.fullmatch(want, have, re.DOTALL) is not None
    h, w = have.lower(), want.lower()
    if "contains" in mods:
        return w in h
    if "startswith" in mods:
        return h.startswith(w)
    if "endswith" in mods:
        return h.endswith(w)
    return h == w


def _field(event, spec, wanted):
    field, *mods = spec.split("|")
    wanted = [str(w) for w in (wanted if isinstance(wanted, list) else [wanted])]
    haves = _values(event, field)
    hit = lambda w: any(_one(h, w, mods) for h in haves)
    return all(map(hit, wanted)) if "all" in mods else any(map(hit, wanted))


def _selection(event, sel):
    if isinstance(sel, list):
        return any(_selection(event, s) for s in sel)
    return all(_field(event, k, v) for k, v in sel.items())


def rule_matches(rule_path, event):
    det = yaml.safe_load(Path(rule_path).read_text())["detection"]
    names = [k for k in det if k != "condition"]
    tokens = re.findall(r"\(|\)|[\w.*-]+", det["condition"])
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def group(quant, target):
        pool = names if target == "them" else [n for n in names if re.fullmatch(target.replace("*", ".*"), n)]
        results = [_selection(event, det[n]) for n in pool]
        return all(results) if quant == "all" else any(results)

    def expr():
        val = term()
        while peek() == "or":
            take()
            rhs = term()
            val = val or rhs
        return val

    def term():
        val = factor()
        while peek() == "and":
            take()
            rhs = factor()
            val = val and rhs
        return val

    def factor():
        tok = take()
        if tok == "not":
            return not factor()
        if tok == "(":
            val = expr()
            take()  # ")"
            return val
        if tok in ("1", "all") and peek() == "of":
            take()
            return group(tok, take())
        return _selection(event, det[tok])

    result = expr()
    assert pos == len(tokens), f"unparsed condition tokens: {tokens[pos:]}"
    return result
