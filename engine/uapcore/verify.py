"""Independent verifier: own key, own seed, held-out bases, its own boundary search. Never sees synthesizer probes."""
import hmac, hashlib, json, random
from .discovery import boundary_seek, bisect_crossing, refine_threshold, _changed

def verify(carrier, synth, seed):
    rng = random.Random(seed); dom = synth["domains"]
    bases = [{k: rng.choice(v) for k, v in dom.items()} for _ in range(8)]
    numeric = [i for i in synth["inputs"] if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in dom[i])]
    out = []
    for c in synth["candidates"]:
        i, o = c["input"], c["output"]; witness = None
        cr = boundary_seek(carrier, bases[:3], [o], numeric); pts = list(bases)
        for x in cr:
            b0 = dict(x["point"]); b0[x["input"]] = x["point"][x["input"]] // x["factor"] if isinstance(x["point"][x["input"]], int) else x["point"][x["input"]] / x["factor"]
            t = bisect_crossing(carrier, x, carrier.run(b0).get(o)); pts += [x["point"], t["below"], t["above"]]
            for r in refine_threshold(carrier, t, numeric): pts += [r["below"], r["above"]]   # its own tight thresholds
        for b in pts:
            r0 = carrier.run(b)
            for v in dom[i]:
                if v == b.get(i): continue
                q = dict(b); q[i] = v
                if _changed(carrier.run(q).get(o), r0.get(o)): witness = {"base": b, "value": v}; break
            if witness: break
        out.append({"consequence": f"dep:{o}<-{i}", "constant_value": "true" if witness else None, "witness": witness})
    return out

def sign(key, obj): return hmac.new(key, json.dumps(obj, sort_keys=True, default=str).encode(), hashlib.sha256).hexdigest()
def check(key, obj, sig): return hmac.compare_digest(sign(key, obj), sig)
