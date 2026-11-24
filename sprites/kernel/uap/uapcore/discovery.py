"""Carrier-independent discovery: twin gate, matched-pair sensitivity, boundary-seeking probes,
negative-reference admission. Synthesizer side: proposes candidates, never settles."""
import json, math, random

def cp_upper_zero(n, alpha=0.05): return 1 - alpha ** (1 / n)     # exact one-sided Clopper-Pearson for 0/n

def inventory_from_window(window):
    ins = sorted({k for q, _ in window for k in q}); outs = sorted({k for _, r in window for k in r})
    dom = {k: sorted({json.dumps(q[k], default=str) for q, _ in window if k in q}) for k in ins}
    return ins, outs, {k: [json.loads(v) for v in vs] for k, vs in dom.items()}

TWIN_SPAN_S = 0.0   # seconds the replays must span; set per target so slow-changing outputs (TTLs, clocks) cannot hide

def twin_gate(carrier, base, outputs, n=29, alpha=0.05, max_rate=0.10, span_s=None):
    """Replay one request n times, spread evenly over span_s seconds. An output with any change is NONDETERMINISTIC
    (mechanism veto). With zero changes, the exact upper bound on its change rate is 1 - alpha**(1/n); n=29 certifies
    <= 10% at 95%, and only for changes on timescales shorter than the span."""
    import time as _t
    span = TWIN_SPAN_S if span_s is None else span_s; rs = []
    for k in range(n):
        rs.append(carrier.run(base))
        if span and k < n - 1: _t.sleep(span / (n - 1))
    nondet = set()
    for o in outputs:
        if any(json.dumps(r.get(o), default=str) != json.dumps(rs[0].get(o), default=str) for r in rs[1:]): nondet.add(o)
    bound = cp_upper_zero(n, alpha)
    return nondet, {"replays": n, "span_s": span, "upper_bound_change_rate": round(bound, 4), "certified": bound <= max_rate}

def _changed(a, b): return json.dumps(a, default=str) != json.dumps(b, default=str)

def pair_sensitivity(carrier, bases, inputs, outputs, dom, rng, legs=2):
    score = {(i, o): [0, 0] for i in inputs for o in outputs}; witness = {}
    for b in bases:
        r0 = carrier.run(b)
        for i in inputs:
            alts = [v for v in dom[i] if v != b.get(i)]
            for v in rng.sample(alts, min(legs, len(alts))):
                q = dict(b); q[i] = v; r = carrier.run(q)
                for o in outputs:
                    score[(i, o)][1] += 1
                    if _changed(r.get(o), r0.get(o)):
                        score[(i, o)][0] += 1; witness.setdefault((i, o), (b, i, v))
    return {k: (c / n if n else 0.0) for k, (c, n) in score.items()}, witness

def boundary_seek(carrier, bases, silent_outputs, numeric_inputs, cap=64):
    """RIA-lite: for outputs that never varied, push each numeric input geometrically (x2 ... x cap) from each base
    until the output changes. Returns crossing points (bases sitting just past a boundary)."""
    crossings = []
    for o in silent_outputs:
        for b in bases:
            r0 = carrier.run(b)
            for i in numeric_inputs:
                f = 2
                while f <= cap:
                    q = dict(b); q[i] = b[i] * f if isinstance(b[i], (int, float)) else b[i]
                    if isinstance(b[i], int): q[i] = int(q[i])
                    if _changed(carrier.run(q).get(o), r0.get(o)):
                        crossings.append({"output": o, "input": i, "factor": f, "point": q}); break
                    f *= 2
            if any(c["output"] == o for c in crossings): break
    return crossings

def bisect_crossing(carrier, crossing, base_out, tol=1e-3, max_steps=24):
    """Narrow a crossing to the threshold: find adjacent input values lo (no change) and hi (changed).
    Returns probe bases on both sides of the threshold, where categorical switches can cross it."""
    o, i, q = crossing["output"], crossing["input"], dict(crossing["point"])
    lo, hi = q[i] / 2, q[i]; is_int = isinstance(q[i], int)
    def changed(v):
        x = dict(q); x[i] = int(v) if is_int else v
        return _changed(carrier.run(x).get(o), base_out)
    for _ in range(max_steps):
        if (is_int and hi - lo <= 1) or (not is_int and hi - lo <= tol * max(1.0, abs(hi))): break
        mid = (lo + hi) // 2 if is_int else (lo + hi) / 2
        if changed(mid): hi = mid
        else: lo = mid
    below, above = dict(q), dict(q)
    below[i] = int(lo) if is_int else lo; above[i] = int(hi) if is_int else hi
    return {"output": o, "input": i, "below": below, "above": above}

def refine_threshold(carrier, t, numeric_inputs, base_out=None, max_halvings=8, tol=1e-3, max_steps=30):
    """A threshold found along one input is only as tight as that input's step. Re-pin it along every OTHER numeric
    input, holding the first at its 'above' value: halve that input until the output flips back, then bisect to
    adjacent values. Small categorical effects can then cross the tighter threshold. Returns extra thresholds."""
    out, o = [], t["output"]
    for j in numeric_inputs:
        if j == t["input"]: continue
        hi_pt = dict(t["above"]); v = hi_pt[j]
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v == 0: continue
        is_int = isinstance(v, int); y_hi = carrier.run(hi_pt).get(o)
        lo, found = v, False
        for _ in range(max_halvings):
            lo = lo // 2 if is_int else lo / 2
            if _changed(carrier.run(dict(hi_pt, **{j: lo})).get(o), y_hi): found = True; break
        if not found: continue
        hi = v
        for _ in range(max_steps):
            if (is_int and hi - lo <= 1) or (not is_int and hi - lo <= tol * max(1.0, abs(hi))): break
            mid = (lo + hi) // 2 if is_int else (lo + hi) / 2
            if _changed(carrier.run(dict(hi_pt, **{j: mid})).get(o), y_hi): lo = mid
            else: hi = mid
        out.append({"output": o, "input": j, "below": dict(hi_pt, **{j: lo}), "above": dict(hi_pt, **{j: hi}), "refined_from": t["input"]})
    return out

def categorical_sweep(carrier, thresholds, categorical_inputs, dom):
    """At each threshold point, try EVERY value of every small categorical input (not a random sample): an effect that
    lowers or raises the output only shows when the switch goes in the direction that crosses back."""
    hits, trials = {}, {}
    for t in thresholds:
        for side in ("below", "above"):
            p = t[side]; r0 = carrier.run(p)
            for c in categorical_inputs:
                if len(dom[c]) > 12: continue
                for v in dom[c]:
                    if v == p[c]: continue
                    q = dict(p); q[c] = v; rq = carrier.run(q)
                    key = (c, t["output"]); trials[key] = trials.get(key, 0) + 1
                    if _changed(rq.get(t["output"]), r0.get(t["output"])): hits[key] = hits.get(key, 0) + 1
    return {k: hits.get(k, 0) / n for k, n in trials.items()}

def conformal_p(score, nulls): return (1 + sum(1 for s in nulls if s >= score)) / (1 + len(nulls))

def synthesize(carrier, window, rng, nulls, eps, numeric_inputs=None):
    ins, outs, dom = inventory_from_window(window)
    numeric = numeric_inputs if numeric_inputs is not None else [i for i in ins if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in dom[i])]
    nondet, twin = twin_gate(carrier, window[0][0], outs)
    varying = {o for o in outs if len({json.dumps(r.get(o), default=str) for _, r in window}) > 1}
    silent = [o for o in outs if o not in varying and o not in nondet]
    bases = [q for q, _ in rng.sample(window, min(8, len(window)))]
    crossings = boundary_seek(carrier, bases, silent, numeric)
    thresholds = []
    for c in crossings:
        b0 = dict(c["point"]); b0[c["input"]] = c["point"][c["input"]] // c["factor"] if isinstance(c["point"][c["input"]], int) else c["point"][c["input"]] / c["factor"]
        thresholds.append(bisect_crossing(carrier, c, carrier.run(b0).get(c["output"])))
    refined = []
    for t in thresholds: refined += refine_threshold(carrier, t, numeric, carrier.run(t["below"]).get(t["output"]))
    thresholds = thresholds + refined
    probe_bases = bases + [c["point"] for c in crossings] + [t["below"] for t in thresholds] + [t["above"] for t in thresholds]
    ext = {k: list(v) for k, v in dom.items()}
    for c in crossings:
        if c["point"][c["input"]] not in ext[c["input"]]: ext[c["input"]].append(c["point"][c["input"]])
    sens, wit = pair_sensitivity(carrier, probe_bases, ins, [o for o in outs if o not in nondet], ext, rng)
    sweep = categorical_sweep(carrier, thresholds, [i for i in ins if i not in numeric], ext)
    for k, v in sweep.items():
        if k[1] not in nondet and v > sens.get(k, 0.0): sens[k] = v
    cands, decisions = [], {}
    for (i, o) in [(i, o) for i in ins for o in outs]:
        key = f"{o}<-{i}"
        if o in nondet: decisions[key] = "NOT_APPLICABLE:NONDETERMINISTIC"; continue
        s = sens.get((i, o), 0.0)
        if s == 0: decisions[key] = "UNRESOLVED:NO_WITNESS"; continue
        p = conformal_p(s, nulls)
        if p <= eps: cands.append({"output": o, "input": i, "score": round(s, 3), "p_false": round(p, 4)}); decisions[key] = "CANDIDATE"
        else: decisions[key] = "UNRESOLVED:BELOW_NEGATIVE_BANK"
    echo = [f'{c["output"]}<-{c["input"]}' for c in cands
            if all(not _changed(r.get(c["output"]), q.get(c["input"])) for q, r in window)]
    return {"inputs": ins, "outputs": outs, "domains": ext, "nondeterministic": sorted(nondet), "twin": twin,
            "silent_in_passive": silent, "crossings": crossings, "thresholds": thresholds, "candidates": cands, "echo_like": echo, "decisions": decisions}

def bank_nulls(neg_carriers, bases, inputs, dom, rng):
    """Null scores from negative references: every (input, output) pair of a system known not to depend on its inputs,
    plus off-diagonal pairs of an echo."""
    nulls = []
    for kind, c in neg_carriers:
        outs = sorted(c.run(bases[0]).keys())
        s, _ = pair_sensitivity(c, bases, inputs, outs, dom, rng)
        nulls += [v for (i, o), v in s.items() if not (kind == "ECHO" and i == o)]
    return nulls
