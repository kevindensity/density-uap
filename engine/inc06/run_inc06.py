"""UAP increment 06: descent levels 4-7 (file drops, inferred wire protocol, terminal screen, behaviour only).
Same discovery engine and verifier as INC-02..05, unchanged. One recorded run:
freeze sources and truth hash -> run every leg -> seal predictions -> open truth -> score."""
import hashlib, json, os, random, sys, tempfile, time
ROOT = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(ROOT)
sys.path.insert(0, BASE); sys.path.insert(0, os.path.join(ROOT, "fixtures"))
from uapcore.discovery import synthesize, bank_nulls, inventory_from_window
from uapcore.verify import verify
from uapcore.descent import FileDropCarrier, WireCarrier, ScreenCarrier, BehaviorCarrier
import batch_daemon, wire_server, behavior_service

R = os.environ.get("INC06_RESULTS", os.path.join(BASE, "inc06_results")); os.makedirs(R, exist_ok=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
SRC = ["uapcore/discovery.py", "uapcore/verify.py", "uapcore/descent.py", "inc06/run_inc06.py", "inc06/fixtures/batch_daemon.py",
       "inc06/fixtures/wire_server.py", "inc06/fixtures/screen_app.py", "inc06/fixtures/behavior_service.py"]
for p in ["uapcore/discovery.py", "uapcore/verify.py", "uapcore/descent.py"]:
    assert "HIDDEN_TRUTH" not in open(os.path.join(BASE, p)).read(), p        # the engine never sees the truth
freeze = {"source": {p: sha(os.path.join(BASE, p)) for p in SRC}, "hidden_truth_sha256": sha(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH.json")), "at": time.time()}
json.dump(freeze, open(os.path.join(R, "FREEZE.json"), "w"), indent=2)

SEED = int.from_bytes(os.urandom(4), "big"); rng = random.Random(SEED); EPS = 0.05

class Deterministic:
    """A negative reference contributes only outputs its own twin gate certifies as deterministic: a changing
    output of a system that ignores its inputs is noise, not evidence about inputs."""
    def __init__(self, c, base):
        from uapcore.discovery import twin_gate
        self.c = c; outs = sorted(c.run(base).keys()); self.nondet, _ = twin_gate(c, base, outs, n=12)
    def run(self, q): return {k: v for k, v in self.c.run(q).items() if k not in self.nondet}

MIN_NULLS = 19                                   # conformal p <= 0.05 is reachable only with at least 19 null scores

def run_leg(name, carrier, window, negs):
    negs = [(k, Deterministic(c, window[0][0])) for k, c in negs]
    ins, outs, dom = inventory_from_window(window); bases = [q for q, _ in rng.sample(window, min(8, len(window)))]
    nulls = bank_nulls(negs, bases, ins, dom, rng)
    assert len(nulls) >= MIN_NULLS, f"NEGATIVE_BANK_TOO_SMALL: {name} has {len(nulls)} null scores"
    calls = {"n": 0}; orig = carrier.run
    def counted(x): calls["n"] += 1; return orig(x)
    carrier.run = counted
    t0 = time.time(); synth = synthesize(carrier, window, rng, nulls, EPS); ver = verify(carrier, synth, rng.randrange(2**31)); carrier.run = orig
    settled = sorted(r["consequence"] for r in ver if r["constant_value"] == "true")
    neg_kind, neg = negs[0]; neg_window = [(q, neg.run(q)) for q, _ in window[:24]]
    neg_synth = synthesize(neg, neg_window, random.Random(rng.randrange(2**31)), nulls, EPS)
    return {"leg": name, "descent_level": carrier.descent_level, "carrier_class": carrier.carrier_class, "inputs": ins, "outputs": outs,
            "settled": settled, "nondeterministic": synth["nondeterministic"], "echo_like": synth["echo_like"], "twin": synth["twin"],
            "silent_in_passive": synth["silent_in_passive"], "crossings": [{k: c[k] for k in ("output", "input", "factor")} for c in synth["crossings"]],
            "thresholds": [{"output": t["output"], "input": t["input"], "below": t["below"][t["input"]], "above": t["above"][t["input"]]} for t in synth["thresholds"]],
            "candidates": synth["candidates"], "n_nulls": len(nulls), "probe_calls": calls["n"], "seconds": round(time.time() - t0, 1),
            "negative_reference_candidates": len(neg_synth["candidates"]), "negative_filtered_outputs": {k: sorted(c.nondet) for k, c in negs}, "decisions": synth["decisions"]}

legs = {}
# ---- level 4: file drops ----
froot, nroot = tempfile.mkdtemp(), tempfile.mkdtemp()
eroot = tempfile.mkdtemp()
batch_daemon.start(froot); batch_daemon.seed_archive(froot, rng); batch_daemon.start(nroot, "constant"); batch_daemon.start(eroot, "echo")
fc = FileDropCarrier(froot); fwin = fc.passive_window(40); ledger_before = fc.ledger_digest()
legs["file"] = run_leg("IBS-7 batch invoicing", fc, fwin, [("CONSTANT", FileDropCarrier(nroot)), ("ECHO", FileDropCarrier(eroot))])
legs["file"].update({"archive_pairs": len(fwin), "ledger_unchanged_by_probing": fc.ledger_digest() == ledger_before})

# ---- level 5: undocumented wire protocol ----
wire_server.serve(8911); wire_server.serve(8912, "constant"); wire_server.serve(8913, "constant_b")
wc = WireCarrier("127.0.0.1", 8911, wire_server.tap(8911, rng)); wneg = WireCarrier("127.0.0.1", 8912, wire_server.tap(8912, rng), grammar_from=wc)
legs["protocol"] = run_leg("pricing server (binary, undocumented)", wc, wc.passive_window(40), [("CONSTANT", wneg), ("CONSTANT_B", WireCarrier("127.0.0.1", 8913, wire_server.tap(8913, rng), grammar_from=wc))])
legs["protocol"].update({"grammar": wc.grammar_report(), "roundtrip_exact": wc.roundtrip_ok()})

# ---- level 6: terminal screen ----
app = os.path.join(ROOT, "fixtures", "screen_app.py")
sc = ScreenCarrier([sys.executable, app]); sneg = ScreenCarrier([sys.executable, app, "constant"])
sdom = {"CLAIM AMOUNT": [350.0, 800.0, 1200.0, 1800.0], "POLICY TYPE": ["H", "A", "L"], "DAYS SINCE LOSS": [2, 5, 9, 14], "BRANCH": ["SFO", "LAX", "SEA"], "ADJUSTER NOTE": ["hail", "water", "theft", "fire"]}
recording = []
for _ in range(40):                                   # an operator session recording: keystrokes and the final screen
    q = {k: rng.choice(v) for k, v in sdom.items()}; keys = "\t".join(str(q[f]) for f in sc.fields) + "\n"
    recording.append((keys, sc._screens(keys)[-1]))
legs["ui"] = run_leg("CT-400 claims triage (green screen)", sc, sc.passive_window(recording), [("CONSTANT", sneg), ("CONSTANT_B", ScreenCarrier([sys.executable, app, "constant_b"]))])
legs["ui"]["form_fields"] = sc.fields

# ---- level 7: behaviour only ----
bc = BehaviorCarrier(behavior_service.call); bneg = BehaviorCarrier(lambda q: behavior_service.call(q, "constant"))
bdom = {"qty": [5, 20, 40, 80, 120], "unit_price": [10.0, 25.0, 60.0], "priority": ["LOW", "HIGH"], "note": ["a1", "b2", "c3"]}
traffic = []
for _ in range(40):
    q = {k: rng.choice(v) for k, v in bdom.items()}; a, ms = bc._measure(q); traffic.append((q, a, ms))
bwin = bc.window_from_traffic(traffic); bnegs = [("CONSTANT", bneg)]
for m in ("constant_b", "constant_c"): bnegs.append((m.upper(), BehaviorCarrier(lambda q, m=m: behavior_service.call(q, m))))
for _, c in bnegs: c.window_from_traffic([(q, *c._measure(q)) for q, _, _ in traffic[:12]])
legs["behavior"] = run_leg("acceptance service (behaviour only)", bc, bwin, bnegs)
legs["behavior"].update({"latency_levels_ms": [round(x, 2) for x in bc.levels], "epistemic": "INFERRED_FROM_BEHAVIOUR"})

pred = {"seed": SEED, "legs": legs}
json.dump(pred, open(os.path.join(R, "PREDICTIONS.json"), "w"), indent=2, default=str)
pred_hash = sha(os.path.join(R, "PREDICTIONS.json"))

# ---- open truth, score ----
T = json.load(open(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH.json")))
def deps(t): return {f"dep:{o}<-{i}" for o, ins in t.items() if not o.startswith("_") for i in ins}
score = {"predictions_sha256": pred_hash, "freeze": freeze["hidden_truth_sha256"], "legs": {}}
for leg in ("file", "protocol", "ui", "behavior"):
    L, t = legs[leg], T[leg]; truth = deps(t); s = set(L["settled"])
    g = {"zero_false_promotions": not (s - truth), "nondeterministic_caught": all(x in L["nondeterministic"] for x in t["_nondeterministic"]),
         "echo_flagged": all(e in L["echo_like"] for e in t.get("_echo", [])), "twin_certified_cp": L["twin"]["certified"],
         "negative_reference_yields_no_claims": L["negative_reference_candidates"] == 0}
    if leg == "file": g.update({"probing_left_no_effect": L["ledger_unchanged_by_probing"], "archive_pairs_reconstructed": L["archive_pairs"] == 40})
    if leg == "protocol":
        gr = L["grammar"]
        g.update({"unique_grammar_matches_truth": gr["request_header"] == t["_grammar"]["request_header"] and gr["response_header"] == t["_grammar"]["response_header"],
                  "wrong_grammars_rejected": gr["request_grammars_rejected"] > 0 and gr["response_grammars_rejected"] > 0, "frames_roundtrip_exact": L["roundtrip_exact"]})
    if leg == "ui": g["form_fields_found_from_screen"] = L["form_fields"] == t["_fields"]
    if leg == "behavior": g["raw_timing_never_settled"] = not any("raw_latency_ms" in c for c in s)
    score["legs"][leg] = {"descent_level": L["descent_level"], "gates": g, "passed": sum(g.values()), "total": len(g),
                          "recall": round(len(s & truth) / len(truth), 3), "false_promotions": sorted(s - truth), "missed": sorted(truth - s),
                          "probe_calls": L["probe_calls"], "seconds": L["seconds"]}
score["totals"] = {"passed": sum(v["passed"] for v in score["legs"].values()), "total": sum(v["total"] for v in score["legs"].values())}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2)
print(json.dumps(score, indent=2))
