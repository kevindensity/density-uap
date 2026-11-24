"""UAP port pipeline (synthesizer side). Sees only HTTP responses. No access to fixture source or truth."""
import json, random, urllib.request, hmac, hashlib

class HttpCarrier:
    """Seven-verb carrier over HTTP; science-free."""
    def __init__(self, base): self.base = base
    def _req(self, method, path, body=None, timeout=5):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=timeout) as resp: return json.loads(resp.read() or b"{}")
    def identity(self): return self._req("GET", "/")
    def run(self, path, body): return self._req("POST", path, body)
    def observe(self, path): return self._req("GET", path)
    def seal(self, obj): return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

def passive_window(carrier, traffic):
    """Rung 1: observe naturally occurring request/response pairs."""
    return [(q, carrier.run("/api/quote", q)) for q in traffic]

def inventory(window):
    inputs = sorted({k for q, _ in window for k in q}); outputs = sorted({k for _, r in window for k in r})
    domains = {k: sorted({json.dumps(q[k]) for q, _ in window}) for k in inputs}
    return inputs, outputs, {k: [json.loads(v) for v in vs] for k, vs in domains.items()}

def twin_gate(carrier, path, window, reps=3):
    """Stage 0 mechanism veto: outputs that change under identical replay are NONDETERMINISTIC."""
    nondet = set()
    for q, _ in window[:5]:
        rs = [carrier.run(path, q) for _ in range(reps)]
        for k in rs[0]:
            if any(r.get(k) != rs[0].get(k) for r in rs[1:]): nondet.add(k)
    return nondet

def sensitivity(carrier, path, bases, inputs, outputs, domains, rng, legs=2):
    """Matched-state paired probes: change one input to another in-domain value, compare outputs."""
    score = {(i, o): [0, 0] for i in inputs for o in outputs}
    for b in bases:
        base_r = carrier.run(path, b)
        for i in inputs:
            alts = [v for v in domains[i] if v != b[i]]
            for v in rng.sample(alts, min(legs, len(alts))):
                q = dict(b); q[i] = v; r = carrier.run(path, q)
                for o in outputs:
                    if o in base_r:
                        score[(i, o)][1] += 1; score[(i, o)][0] += int(r.get(o) != base_r.get(o))
    return {k: (c / n if n else None) for k, (c, n) in score.items()}

def negative_bank_scores(carrier, bases, inputs, domains, rng):
    """Known-null pairs from systems that fool discovery (Section 9.5)."""
    nulls = []
    for path in ["/neg/constant", "/neg/cache", "/neg/clip"]:
        s = sensitivity(carrier, path, bases, inputs, ["total", "tax", "status"], domains, rng)
        nulls += [v for v in s.values() if v is not None]
    s = sensitivity(carrier, "/neg/echo", bases, inputs, inputs, domains, rng)   # echo: off-diagonal pairs are null
    nulls += [v for (i, o), v in s.items() if i != o and v is not None]
    return nulls

def conformal_p(score, nulls):
    return (1 + sum(1 for s in nulls if s >= score)) / (1 + len(nulls))

def synthesize(carrier, traffic, seed, eps):
    rng = random.Random(seed)
    window = passive_window(carrier, traffic)
    inputs, outputs, domains = inventory(window)
    nondet = twin_gate(carrier, "/api/quote", window)
    varying = {o for o in outputs if len({json.dumps(r.get(o)) for _, r in window}) > 1}
    bases = [q for q, _ in rng.sample(window, 8)]
    sens = sensitivity(carrier, "/api/quote", bases, inputs, outputs, domains, rng)
    nulls = negative_bank_scores(carrier, bases, inputs, domains, rng)
    candidates, decisions = [], {}
    for (i, o), s in sens.items():
        if o in nondet: decisions[f"{o}<-{i}"] = "NOT_APPLICABLE:NONDETERMINISTIC"; continue
        if s is None or s == 0: decisions[f"{o}<-{i}"] = "UNRESOLVED:NO_WITNESS"; continue   # silence is not absence
        p = conformal_p(s, nulls)
        if p <= eps: candidates.append({"output": o, "input": i, "score": s, "p_false": p}); decisions[f"{o}<-{i}"] = "CANDIDATE"
        else: decisions[f"{o}<-{i}"] = "UNRESOLVED:BELOW_NEGATIVE_BANK"
    echo = [c for c in candidates if all(json.dumps(r.get(c["output"])) == json.dumps(q.get(c["input"])) for q, r in window)]
    return {"identity": carrier.identity(), "inputs": inputs, "outputs": outputs, "nondeterministic": sorted(nondet),
            "never_varied_in_passive": sorted(set(outputs) - varying - nondet), "n_negative_nulls": len(nulls),
            "candidates": candidates, "echo_like": [f'{c["output"]}<-{c["input"]}' for c in echo],
            "decisions": decisions, "domains": domains}

def sign(key, obj): return hmac.new(key, json.dumps(obj, sort_keys=True).encode(), hashlib.sha256).hexdigest()
