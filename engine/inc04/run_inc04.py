"""UAP increment 04: grammar beyond single-field dependencies. Custody-bound one-shot run."""
import hashlib, json, os, random, sys, time, uuid, itertools, subprocess
import psycopg2
ROOT = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(ROOT)
sys.path.insert(0, BASE); sys.path.insert(0, os.path.join(ROOT, "fixtures")); sys.path.insert(0, "/home/claude/vault")
from uapcore.carriers import HttpCarrier, SqlCarrier, CliCarrier, h
from uapcore.discovery import synthesize, bank_nulls, inventory_from_window, _changed
from uapcore.verify import verify, sign, check
from uapcore.store import Store, sj
from uapcore.grammar import UNRESOLVED, Recording, interactions, categorical_outputs, magnitude_relations, cegis_partition, counterexample_search, run_program, TOL
from uapcore.grammar_verify import verify_interaction, verify_rule, _points
from densvault.core import Vault
import api_oms
R = os.path.join(BASE, "inc04_results"); os.makedirs(R, exist_ok=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
SRC = ["uapcore/carriers.py", "uapcore/discovery.py", "uapcore/verify.py", "uapcore/store.py", "uapcore/grammar.py", "uapcore/grammar_verify.py",
       "inc04/run_inc04.py", "supabase/migrations/0001_uap_safety_spine.sql", "supabase/migrations/0002_uap_canonical.sql",
       "supabase/migrations/0003_uap_grant_epoch.sql", "supabase/migrations/0004_uap_finality.sql"]
_v = Vault(os.environ.get("VAULT_DIR", "/home/claude/demo/vault")); _e = _v.find_entry(os.environ["VAULT_RUN_ID"])
_frozen = {f["path"]: f["sha256"] for f in _v.manifest(_e["manifest_sha256"])["files"]}
_mm = [p for p in SRC if _frozen.get(p) != sha(os.path.join(BASE, p))]
assert not _mm and _e["kind"] == "ORIGINAL_FREEZE", f"CUSTODY_MISMATCH {_mm}"
CUSTODY = {"vault_run_id": _e["run_id"], "merkle_root": _e["merkle_root"], "kind": _e["kind"]}
for p in ["uapcore/grammar.py", "uapcore/grammar_verify.py", "uapcore/discovery.py"]:
    s = open(os.path.join(BASE, p)).read(); assert "HIDDEN_TRUTH" not in s, p
json.dump({"custody": CUSTODY, "truth_sha256": sha(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH_GRAMMAR.json"))}, open(os.path.join(R, "FREEZE.json"), "w"), indent=2)

SEED = int.from_bytes(os.urandom(4), "big"); rng = random.Random(SEED); EPS = 0.05; VER_KEY = os.urandom(32)
st = Store(psycopg2.connect(dbname="uapinc4", user="postgres", password="pg", host="127.0.0.1"))
st.q("insert into verify.keys values ('syn-uap','SYNTHESIZER'),('ver-uap','VERIFIER') on conflict do nothing")
def vsettle(ep, key, live):
    s = sign(VER_KEY, {"c": key}); return st.settle_key(ep, key, live, check(VER_KEY, {"c": key}, s))

def run_leg(name, raw, window_inputs, negs, cls):
    rec = Recording(raw); sysid = st.system(name); ep = st.epoch(sysid, 1, h(raw.identity())); port = st.port(sysid, ep)
    window = [(q, rec.run(q)) for q in window_inputs]
    ins, outs, dom = inventory_from_window(window); bases0 = [q for q, _ in rng.sample(window, 8)]
    for kind, c in negs: st.bank(cls, kind, bank_nulls([(kind, c)], bases0, ins, dom, rng))
    st.lock_threshold(cls, EPS)
    st.cur.execute("select score from uap.negative_scores s join uap.negative_references r on r.id=s.reference_id where r.carrier_class=%s", (cls,))
    nulls = [float(x[0]) for x in st.cur.fetchall()]
    synth = synthesize(rec, window, rng, nulls, EPS); ver = verify(raw, synth, rng.randrange(2**31)); live = sj(synth["decisions"])
    deps = {}
    for r in ver:
        if r["constant_value"]:
            vsettle(ep, r["consequence"], live); o, i = r["consequence"][4:].split("<-"); deps.setdefault(o, set()).add(i)
    excl = set(synth["nondeterministic"]) | {e.split("<-")[0] for e in synth["echo_like"]}
    deps_g = {o: v for o, v in deps.items() if o not in excl and len(v) >= 2}
    dom = synth["domains"]; tpts = [t["below"] for t in synth["thresholds"]] + [t["above"] for t in synth["thresholds"]]
    bases = bases0 + tpts
    # joint dependencies
    cands, tested = interactions(rec, deps_g, bases, dom, rng); joint = []
    for c in cands:
        if verify_interaction(raw, c, dom, rng.randrange(2**31)):
            key = f"int:{c['output']}<-{'*'.join(c['pair'])}"; sid = vsettle(ep, key, live)
            st.projection_of(ep, sid, "DEPENDENCY", {"output": c["output"], "joint": c["pair"]},
                             ["functional form", "sign or size of the interaction", "absence of other interactions"], ["MONITOR", "EXPLAIN"], ["DELETE", "IRREVERSIBLE_WRITE"])
            joint.append(c)
    # magnitude relations, each verified against the verifier's own threshold-localized probes
    cats = categorical_outputs(rec.log, excl); rel_c = magnitude_relations(rec.log, cats, excl); rels = []
    vrng, vb, vpts = _points(raw, dom, rng.randrange(2**31), rel_c)
    for rel in rel_c:
        prog = {"kind": "threshold", "on": rel["on"], "cut_after": rel["cut_after"], "cut_upto": rel["cut_upto"], "below": rel["below"], "above": rel["above"]}
        if verify_rule(raw, prog, rel["output"], vpts) is None:
            key = f"mag:{rel['output']}|{rel['on']}>({rel['cut_after']},{rel['cut_upto']}]"; sid = vsettle(ep, key, live)
            st.projection_of(ep, sid, "MAGNITUDE_RELATION", rel, ["exact cut inside the bracket", "behaviour outside the tested range"],
                             ["MONITOR", "EXPLAIN", "ALERT_NEAR_THRESHOLD"], ["DELETE", "IRREVERSIBLE_WRITE"])
            rels.append(rel)
        else: rel["refuted"] = True
    # partitions by counterexample-guided synthesis
    parts = {}
    for o in cats:
        if o not in deps: continue
        oracle = counterexample_search(rec, o, dom, bases + tpts, rng)
        prog, lang, trace = cegis_partition(o, rec.log, deps[o], rels, oracle)
        entry = {"language": lang, "trace": trace, "program": prog, "certified": False}
        if prog is not None and verify_rule(raw, prog, o, vpts) is None:
            sid = vsettle(ep, f"part:{o}:{sj(prog)[:16]}", live)
            st.projection_of(ep, sid, "PARTITION", {"output": o, "program": prog}, ["values never observed", "inputs outside the tested domain"],
                             ["MONITOR", "EXPLAIN", "PREDICT_FOR_PLANNING"], ["DELETE", "IRREVERSIBLE_WRITE", "FINANCIAL_POSTING"])
            entry["certified"] = True
        parts[o] = entry
    return {"settled_single": sorted(f"dep:{o}<-{i}" for o, v in deps.items() for i in v), "joint_tested": tested,
            "joint": [{"output": c["output"], "pair": c["pair"], "witness": c["witness"]} for c in joint],
            "magnitude_candidates": rel_c, "magnitude": rels, "partitions": parts, "probe_calls": len(rec.log),
            "domains": dom, "nondeterministic": synth["nondeterministic"], "echo": synth["echo_like"]}

legs = {}
srv = api_oms.serve(8768); base = "http://127.0.0.1:8768"; time.sleep(0.3); api = HttpCarrier(base, "/api/quote")
dom_api = {"qty": [1, 2, 3, 5, 8], "unit_price": [5.0, 12.5, 19.99, 40.0], "discount_code": ["NONE", "VIP", "STAFF", "PROMO5"],
           "region": ["CA", "TX", "OR", "NY"], "note": ["a", "b", "c"], "ts": [1700000000 + i for i in range(5)]}
traffic = [{k: rng.choice(v) for k, v in dom_api.items()} for _ in range(40)]
legs["api"] = run_leg("LEGACY-OMS", api, traffic, [("CONSTANT", api.with_path("/neg/constant")), ("MASKING_CACHE", api.with_path("/neg/cache")),
                       ("CLIPPING_LIMITER", api.with_path("/neg/clip")), ("ECHO", api.with_path("/neg/echo"))], "api")
erp = "dbname=legacy_erp4 user=postgres password=pg host=127.0.0.1"; db = SqlCarrier(erp, "quote_requests", "quote_view")
legs["db"] = run_leg("LEGACY-ERP", db, [q for q, _ in db.passive_window(40)], [("CONSTANT", SqlCarrier(erp, "quote_requests", "neg_constant")),
                     ("CLIPPING_LIMITER", SqlCarrier(erp, "quote_requests", "neg_clip")), ("ECHO", SqlCarrier(erp, "quote_requests", "neg_echo"))], "db")
F = os.path.join(ROOT, "fixtures"); cli = CliCarrier([sys.executable, os.path.join(F, "legacy_rate.py")])
cin = [CliCarrier.parse_log_line(l) for l in open(os.path.join(F, "legacy_rate_invocations.log")).read().splitlines()]
legs["cli"] = run_leg("RATE-TOOL", cli, cin, [("CONSTANT", CliCarrier([sys.executable, os.path.join(F, "neg_constant.py")])),
                       ("ECHO", CliCarrier([sys.executable, os.path.join(F, "neg_echo.py")]))], "cli")

pred = {"seed": SEED, "custody": CUSTODY, "legs": legs}
json.dump(pred, open(os.path.join(R, "PREDICTIONS.json"), "w"), indent=2, default=str); pred_hash = sha(os.path.join(R, "PREDICTIONS.json"))

# ===== scoring: truth opened only now; reference functions are the fixtures themselves, queried by the scorer =====
T = json.load(open(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH_GRAMMAR.json")))
ref = {"api": lambda q: api_oms.quote(dict(q, channel="STORE")), "db": SqlCarrier(erp, "quote_requests", "quote_view").run, "cli": cli.run}
def norm_pairs(lst): return {(o, tuple(sorted(p))) for o, ps in lst.items() for p in ps}
score = {"predictions_sha256": pred_hash, "custody": CUSTODY, "legs": {}}
srng = random.Random(SEED ^ 0x5EED)
for leg, L in legs.items():
    t = T[leg]; f = ref[leg]
    claimed = {(c["output"], tuple(sorted(c["pair"]))) for c in L["joint"]}; truth_pairs = norm_pairs(t["interactions"])
    def reproduces(c):                                         # scorer replays the claimed witness on the reference function
        w = c["witness"]; i, j = c["pair"]; b = w["base"]
        vals = [f(p).get(c["output"]) for p in (b, dict(b, **{i: w["vi"]}), dict(b, **{j: w["vj"]}), dict(b, **{i: w["vi"], j: w["vj"]}))]
        if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in vals): return abs(vals[3] - vals[2] - vals[1] + vals[0]) > TOL
        return _changed(vals[0], vals[1]) != _changed(vals[2], vals[3])
    false_int = [c for c in L["joint"] if not reproduces(c) or (c["output"], tuple(sorted(c["pair"]))) not in truth_pairs]
    additive = {(a[0], tuple(sorted(a[1:]))) for a in t["additive_pairs_must_not_be_claimed"]}
    mag_ok = []
    for m in t["magnitude"]:
        hit = [r for r in L["magnitude"] if r["output"] == m["output"] and r["on"] == m["on"]]
        mag_ok.append(bool(hit) and all(r["cut_after"] <= m["cut"] < r["cut_upto"] and r["above"] == m["above"] for r in hit))
    spurious_mag = [r for r in L["magnitude"] if not any(r["output"] == m["output"] and r["on"] == m["on"] for m in t["magnitude"])]
    # partition programs scored on the scorer's own grid: random points plus a numeric sweep across thresholds
    dom = L["domains"]; grid = [{k: srng.choice(v) for k, v in dom.items()} for _ in range(120)]
    nums = [k for k, v in dom.items() if all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in v)]
    for b in grid[:12]:
        for k in nums:
            for fct in (2, 3, 4, 6, 8, 12, 16, 24, 32, 48):
                grid.append(dict(b, **{k: (int(b[k] * fct) if isinstance(b[k], int) else b[k] * fct)}))
    part_acc = {}
    for o, P in L["partitions"].items():
        if not P["certified"]: part_acc[o] = None; continue
        decided = agree = 0
        for q in grid:
            r = f(q); y = run_program(P["program"], q, r)
            if y == UNRESOLVED: continue
            decided += 1; agree += json.dumps(y, default=str) == json.dumps(r.get(o), default=str)
        part_acc[o] = {"accuracy_on_decided": round(agree / decided, 4) if decided else None, "abstained": len(grid) - decided}
    g = {"zero_false_joint_dependencies": not false_int, "additive_pairs_not_claimed": not (claimed & additive),
         "magnitude_relations_correct": all(mag_ok), "no_spurious_magnitude_relation": not spurious_mag,
         "expected_partitions_certified": all(L["partitions"].get(o, {}).get("certified") for o in t["partitions"]),
         "certified_partitions_exact_on_decided_points": all(a["accuracy_on_decided"] == 1.0 for a in part_acc.values() if a is not None)}
    score["legs"][leg] = {"gates": g, "passed": sum(g.values()), "total": len(g),
                          "joint_recall": round(len(claimed & truth_pairs) / len(truth_pairs), 3) if truth_pairs else None,
                          "joint_missed": sorted(f"{o}<-{'*'.join(p)}" for o, p in truth_pairs - claimed),
                          "joint_false": [f"{c['output']}<-{'*'.join(c['pair'])}" for c in false_int],
                          "magnitude": [{k: r[k] for k in ("output", "on", "cut_after", "cut_upto", "above")} for r in L["magnitude"]],
                          "refuted_magnitude_candidates": [f"{r['output']}|{r['on']}" for r in L["magnitude_candidates"] if r.get("refuted")],
                          "partitions": {o: {"language": P["language"], "kind": (P["program"] or {}).get("kind"), "certified": P["certified"],
                                             "scorer_grid_accuracy": part_acc.get(o), "trace": [x["result"][:5] + ":" + x["language"] for x in P["trace"]]}
                                         for o, P in L["partitions"].items()},
                          "grid_points": len(grid), "probe_calls": L["probe_calls"]}
score["totals"] = {"passed": sum(v["passed"] for v in score["legs"].values()), "total": sum(v["total"] for v in score["legs"].values())}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2, default=str); srv.shutdown()
print(json.dumps(score, indent=1, default=str))
