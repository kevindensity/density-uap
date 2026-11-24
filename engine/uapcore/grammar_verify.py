"""Independent verifier for INC-04 grammar claims: own seed, own probe points, own key. A claim is certified only if
the verifier re-finds a witness (interactions) or finds no counterexample in its own search (relations, partitions)."""
import json, random
from .grammar import mixed_witness, run_program, UNRESOLVED
from .discovery import boundary_seek, bisect_crossing

def _points(carrier, dom, seed, rels, n_bases=10):
    rng = random.Random(seed)
    bases = [{k: rng.choice(v) for k, v in dom.items()} for _ in range(n_bases)]
    numeric = [k for k, v in dom.items() if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v)]
    extra = []
    for o in {r["output"] for r in rels}:
        for c in boundary_seek(carrier, bases[:4], [o], numeric):
            b0 = dict(c["point"]); x = c["point"][c["input"]]; b0[c["input"]] = x // c["factor"] if isinstance(x, int) else x / c["factor"]
            t = bisect_crossing(carrier, c, carrier.run(b0).get(o)); extra += [t["below"], t["above"]]
    pts = list(bases) + extra
    for s in list(extra):
        for k, vs in dom.items():
            for v in vs: pts.append(dict(s, **{k: v}))
    return rng, bases, pts

def verify_interaction(carrier, claim, dom, seed):
    rng = random.Random(seed); bases = [{k: rng.choice(v) for k, v in dom.items()} for _ in range(12)]
    bases.append(claim["witness"]["base"])      # the verifier may replay the claimed region, with its own value choices
    return mixed_witness(carrier, claim["output"], claim["pair"][0], claim["pair"][1], bases, dom, rng, legs=3) is not None

def verify_rule(carrier, program, o, pts):
    for q in pts:
        r = carrier.run(q)
        y = run_program(program, q, r)
        if y != UNRESOLVED and json.dumps(y, default=str) != json.dumps(r.get(o), default=str): return {"counterexample": q}
    return None
