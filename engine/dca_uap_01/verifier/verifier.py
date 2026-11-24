"""Independent verifier: separate key, separate seed, held-out bases. Never sees the synthesizer's probes."""
import json, random, hmac, hashlib

def verify(carrier, synth, seed, n_bases=8):
    rng = random.Random(seed); dom = synth["domains"]
    bases = [{k: rng.choice(v) for k, v in dom.items()} for _ in range(n_bases)]
    receipts = []
    for c in synth["candidates"]:
        i, o = c["input"], c["output"]; witness = None
        twin = [carrier.run("/api/quote", bases[0]).get(o) for _ in range(3)]
        deterministic = len({json.dumps(t) for t in twin}) == 1
        for b in bases:
            r0 = carrier.run("/api/quote", b)
            for v in dom[i]:
                if v == b[i]: continue
                q = dict(b); q[i] = v
                if carrier.run("/api/quote", q).get(o) != r0.get(o): witness = (b, v); break
            if witness: break
        receipts.append({"consequence": f"dep:{o}<-{i}", "constant_value": "true" if (witness and deterministic) else None,
                         "witness": witness, "deterministic": deterministic})
    return receipts

def sign(key, obj): return hmac.new(key, json.dumps(obj, sort_keys=True).encode(), hashlib.sha256).hexdigest()
def check(key, obj, sig): return hmac.compare_digest(sign(key, obj), sig)
