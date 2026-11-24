"""INC-05 semantics layer.
bridge inference from anchors on an admissible channel; ICC-001 invariant core across surviving interpretations;
PIE-001 partial interoperability envelopes across systems; MCD-001 minimal consequence distinction."""
import itertools, json

NUMERIC_SCALES = [1.0, 0.01, 100.0, 0.001, 1000.0]          # identity, cents->dollars, dollars->cents, milli, kilo
INTEGER_SCALES = [1.0, 24.0, 1.0 / 7.0]                       # days, hours, weeks

def _close(a, b, unit):
    tol = 0.5 if unit == "cents" else 0.006 * max(1.0, abs(b)) if unit == "usd" else 1e-6 * max(1.0, abs(b))
    return abs(a - b) <= tol

def candidates(kind, native_values):
    if kind == "NUMERIC": return [{"scale": s} for s in NUMERIC_SCALES]
    if kind == "INTEGER": return [{"scale": s} for s in INTEGER_SCALES]
    vals = sorted({json.dumps(v) for v in native_values})            # BOOLEAN: every assignment of native classes to true/false
    if len(vals) != 2: return []
    a, b = (json.loads(v) for v in vals)
    return [{"map": {json.dumps(a): True, json.dumps(b): False}}, {"map": {json.dumps(a): False, json.dumps(b): True}}]

def apply(t, v):
    if "scale" in t: return None if v is None else v * t["scale"]
    return t["map"].get(json.dumps(v))

def infer_bridge(kind, unit, native_observed, anchors):
    """anchors: list of (native_value, canonical_value) from an admissible channel. Returns state + survivors."""
    cands = candidates(kind, native_observed + [a for a, _ in anchors])
    surv = [t for t in cands if all((apply(t, n) == c) if kind == "BOOLEAN" else _close(apply(t, n), c, unit) for n, c in anchors)]
    if not anchors: state = "DOMAIN_LOCAL_ONLY"
    elif not surv: state = "CONTRADICTORY"
    elif len(surv) > 1: state = "DOMAIN_LOCAL_ONLY"
    else:
        t = surv[0]; ident = t.get("scale") == 1.0 or (kind == "BOOLEAN" and all(json.loads(k) is v for k, v in t["map"].items()))
        state = "CANONICAL_EQUIVALENT" if ident else "RECOVERABLE_BY_MAP"
    return {"state": state, "survivors": surv, "anchor_count": len(anchors)}

def holdout_check(kind, unit, native_observed, anchors):
    """Independent verifier: fit on even-indexed anchors, predict odd-indexed ones. Any miss is a counterexample."""
    fit, hold = anchors[0::2], anchors[1::2]
    b = infer_bridge(kind, unit, native_observed, fit)
    if len(b["survivors"]) != 1: return {"ok": len(hold) == 0 and b["state"] != "CONTRADICTORY", "reason": "fit not unique"}
    t = b["survivors"][0]
    miss = [(n, c) for n, c in hold if not ((apply(t, n) == c) if kind == "BOOLEAN" else _close(apply(t, n), c, unit))]
    return {"ok": not miss, "misses": miss, "transform": t}

def invariant_core(kind, survivors, partition_program=None, magnitude=None):
    """ICC-001: the claims every surviving interpretation agrees on, and the cheapest evidence that would separate the rest."""
    core, not_core = [], []
    if not survivors: return {"core": [], "not_core": ["ALL (no interpretation survives)"], "separating_evidence": None}
    if len(survivors) == 1: core.append("VALUE")
    else: not_core.append("VALUE")
    if all("scale" in t and t["scale"] > 0 for t in survivors): core += ["ORDERING", "ZERO_SET", "RATIO_BETWEEN_RECORDS"]
    if all("scale" in t for t in survivors) and len({t["scale"] for t in survivors}) > 1: not_core += ["DIFFERENCES_IN_CANONICAL_UNITS", "CROSS_SYSTEM_SUM"]
    if kind == "BOOLEAN" and len(survivors) > 1: core.append("EQUIVALENCE_CLASSES"); not_core.append("WHICH_CLASS_IS_TRUE")
    if partition_program is not None: core.append("PARTITION_RULE_" + partition_program.get("kind", "?").upper())
    if magnitude is not None:
        core.append("SINGLE_CUT_EXISTS")
        (core if len(survivors) == 1 else not_core).append("CUT_VALUE_IN_CANONICAL_UNITS")
    sep = None if len(survivors) <= 1 else {"evidence": "one anchor record with a nonzero canonical value on an admissible channel", "cost": 1}
    return {"core": core, "not_core": not_core, "separating_evidence": sep}

OPS_RESOLVED = {"NUMERIC": ["CROSS_SUM", "CROSS_COMPARE_ABSOLUTE", "CROSS_RANK"], "INTEGER": ["CROSS_SUM", "CROSS_COMPARE_ABSOLUTE", "CROSS_RANK"],
                "BOOLEAN": ["CROSS_COUNT", "CROSS_EQUALITY"]}
def pie_envelope(bridge_a, bridge_b, ordering_a, ordering_b, mcd=None, kind="NUMERIC"):
    """PIE-001: which cross-system operations the two bridges license for one canonical field."""
    resolved = lambda b: b["state"] in ("CANONICAL_EQUIVALENT", "RECOVERABLE_BY_MAP")
    allowed, forbidden, required = [], [], []
    (allowed if resolved(bridge_a) and resolved(bridge_b) else forbidden).extend(OPS_RESOLVED[kind])
    if ordering_a: allowed.append("WITHIN_A_RANK")
    if ordering_b: allowed.append("WITHIN_B_RANK")
    if mcd is not None:
        if mcd["status"] == "NO_CONFLICT": allowed.append("POLICY_TRANSFER")
        else:
            forbidden.append("POLICY_TRANSFER")
            if mcd["status"] == "DISTINCTION_FOUND": allowed.append("POLICY_TRANSFER_CONDITIONED"); required += mcd["minimal_distinction"]
    return {"allowed": sorted(set(allowed)), "forbidden": sorted(set(forbidden)), "required_distinctions": sorted(set(required))}

def minimal_distinction(records, signature, consequence, extras, max_size=3):
    """MCD-001: smallest set of extra features under which the consequence becomes a function of signature + extras."""
    def conflicts(keys):
        seen, bad = {}, 0
        for r in records:
            k = json.dumps([r[x] for x in keys], default=str)
            if k in seen and seen[k] != r[consequence]: bad += 1
            seen.setdefault(k, r[consequence])
        return bad
    base = conflicts(signature)
    if base == 0: return {"status": "NO_CONFLICT", "conflicts_found": 0, "minimal_distinction": []}
    for size in range(1, max_size + 1):
        for combo in itertools.combinations(sorted(extras), size):
            if conflicts(signature + list(combo)) == 0:
                return {"status": "DISTINCTION_FOUND", "conflicts_found": base, "minimal_distinction": list(combo)}
    return {"status": "NO_DISTINCTION_AVAILABLE", "conflicts_found": base, "minimal_distinction": None}
