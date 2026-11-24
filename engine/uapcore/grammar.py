"""INC-04 grammar layer (synthesizer side), following MCSQ-GEN's counterexample-guided synthesis.
- Joint dependencies: o depends on (i, j) jointly when the effect of i on o changes with j (mixed difference).
- MAGNITUDE_RELATION: a categorical output flips at a threshold on another numeric output; the cut is bracketed.
- Output partitions: a small program for each categorical output, grown through languages L0 -> L1 -> L2
  only when the current language is refuted by counterexamples. Nothing here settles anything."""
import itertools, json, random
from .discovery import _changed

UNRESOLVED = "__UNRESOLVED__"
TOL = 0.025          # rounding floor: four values each rounded to 0.01 can move a mixed difference by at most 0.02

class Recording:
    """Wraps a carrier and keeps every (inputs, outputs) pair it returned."""
    def __init__(self, carrier): self.c, self.log = carrier, []
    def run(self, q):
        r = self.c.run(q); self.log.append((dict(q), dict(r))); return r
    def __getattr__(self, k): return getattr(self.c, k)

def _num(v): return isinstance(v, (int, float)) and not isinstance(v, bool)

def mixed_witness(carrier, o, i, j, bases, dom, rng, legs=2):
    """Return a witness (base, vi, vj, values) where i's effect on o depends on j, or None."""
    for b in bases:
        for vi in rng.sample([v for v in dom[i] if v != b.get(i)], min(legs, max(0, len(dom[i]) - 1))):
            for vj in rng.sample([v for v in dom[j] if v != b.get(j)], min(legs, max(0, len(dom[j]) - 1))):
                p00 = dict(b); p10 = dict(b, **{i: vi}); p01 = dict(b, **{j: vj}); p11 = dict(b, **{i: vi, j: vj})
                f = [carrier.run(p).get(o) for p in (p00, p10, p01, p11)]
                if all(_num(x) for x in f):
                    if abs(f[3] - f[2] - f[1] + f[0]) > TOL: return {"base": b, "vi": vi, "vj": vj, "values": f}
                elif _changed(f[0], f[1]) != _changed(f[2], f[3]):
                    return {"base": b, "vi": vi, "vj": vj, "values": f}
    return None

def interactions(carrier, deps, bases, dom, rng):
    """Test every pair of established single dependencies of each output."""
    found, tested = [], []
    for o, ins in deps.items():
        for i, j in itertools.combinations(sorted(ins), 2):
            w = mixed_witness(carrier, o, i, j, bases, dom, rng); tested.append(f"{o}<-{i}*{j}")
            if w: found.append({"output": o, "pair": [i, j], "witness": w})
    return found, tested

def categorical_outputs(log, exclude):
    vals = {}
    for _, r in log:
        for k, v in r.items():
            if k not in exclude: vals.setdefault(k, set()).add(json.dumps(v, default=str))
    return [k for k, v in vals.items() if 2 <= len(v) <= 8]

def magnitude_relations(log, cat_outputs, exclude):
    """For each categorical output with two classes, find numeric outputs that separate the classes by one cut."""
    rels = []
    for o in cat_outputs:
        classes = sorted({json.dumps(r.get(o), default=str) for _, r in log})
        if len(classes) != 2: continue
        nums = [u for u in log[0][1] if u not in exclude and u != o and all(_num(r.get(u)) for _, r in log)]
        for u in nums:
            lo = [r[u] for _, r in log if json.dumps(r.get(o), default=str) == classes[0]]
            hi = [r[u] for _, r in log if json.dumps(r.get(o), default=str) == classes[1]]
            for below, above, cb, ca in ((lo, hi, classes[0], classes[1]), (hi, lo, classes[1], classes[0])):
                if below and above and max(below) < min(above):
                    rels.append({"output": o, "on": u, "cut_after": max(below), "cut_upto": min(above),
                                 "below": json.loads(cb), "above": json.loads(ca)})
    return rels

# ---------------- partition programs ----------------
def run_program(p, inputs, outputs=None):
    if p["kind"] == "const": return p["value"]
    if p["kind"] == "lookup":
        return p["table"].get(json.dumps([inputs.get(k) for k in p["inputs"]], default=str), "__UNSEEN__")
    if p["kind"] == "threshold":
        u = (outputs or {}).get(p["on"])
        if u is None: return UNRESOLVED
        if u <= p["cut_after"]: return p["below"]
        if u >= p["cut_upto"]: return p["above"]
        return UNRESOLVED            # inside the bracket the cut is not settled: abstain, never guess

def fit(language, o, data, deps_o, rels):
    """Return the simplest program in `language` consistent with every observation, or None."""
    ys = [json.dumps(r.get(o), default=str) for _, r in data]
    if language == "L0":
        if len(set(ys)) == 1: return {"kind": "const", "value": data[0][1].get(o)}
        cands = [[i] for i in sorted(deps_o)]
    elif language == "L1":
        for rel in rels:
            if rel["output"] == o:
                p = {"kind": "threshold", "on": rel["on"], "cut_after": rel["cut_after"], "cut_upto": rel["cut_upto"],
                     "below": rel["below"], "above": rel["above"]}
                if all(json.dumps(run_program(p, q, r), default=str) == y for (q, r), y in zip(data, ys)): return p
        cands = [list(c) for c in itertools.combinations(sorted(deps_o), 2)]
    else:
        cands = [sorted(deps_o)]
    for keys in cands:
        table, ok = {}, True
        for (q, r), y in zip(data, ys):
            k = json.dumps([q.get(x) for x in keys], default=str)
            if table.setdefault(k, y) != y: ok = False; break
        if ok: return {"kind": "lookup", "inputs": keys, "table": {k: json.loads(v) for k, v in table.items()}}
    return None

def cegis_partition(o, data, deps_o, rels, oracle, max_rounds=6):
    """Grow the language only when refuted. `oracle(program)` returns a counterexample (inputs, outputs) or None."""
    data = list(data); trace = []
    for lang in ("L0", "L1", "L2"):
        for _ in range(max_rounds):
            p = fit(lang, o, data, deps_o, rels)
            if p is None: trace.append({"language": lang, "result": "INSUFFICIENT"}); break
            cex = oracle(p)
            if cex is None: trace.append({"language": lang, "result": "NO_COUNTEREXAMPLE"}); return p, lang, trace
            trace.append({"language": lang, "result": "COUNTEREXAMPLE"}); data.append(cex)
    return None, "GENESIS_UNRESOLVED", trace

def counterexample_search(carrier, o, dom, seeds, rng, n=40):
    """Synthesizer-side oracle: probe around seeds (threshold points included) varying every input."""
    pts = []
    for s in seeds:
        for k, vs in dom.items():
            for v in vs: pts.append(dict(s, **{k: v}))
    rng.shuffle(pts)
    def oracle(p):
        for q in pts[:n * 4]:
            r = carrier.run(q)
            y = run_program(p, q, r)
            if y != UNRESOLVED and json.dumps(y, default=str) != json.dumps(r.get(o), default=str): return (q, r)
        return None
    return oracle
