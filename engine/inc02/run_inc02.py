"""UAP increment 02: DCA-UAP-01 across API, DB and CLI carriers, plus DCA-UAP-02 drift/requalification.
One recorded run. Freeze -> commit truth hash -> run every leg -> seal predictions -> open truth -> score."""
import hashlib, json, os, random, sys, time, uuid
import psycopg2
ROOT = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(ROOT)); sys.path.insert(0, os.path.join(ROOT, "fixtures"))
from uapcore.carriers import HttpCarrier, SqlCarrier, CliCarrier, h
from uapcore.discovery import synthesize, bank_nulls, inventory_from_window
from uapcore.verify import verify, sign, check
from uapcore.store import Store, sj
import api_oms
R = os.path.join(ROOT, "results"); os.makedirs(R, exist_ok=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
SRC = ["uapcore/carriers.py", "uapcore/discovery.py", "uapcore/verify.py", "uapcore/store.py", "inc02/run_inc02.py",
       "supabase/migrations/0001_uap_safety_spine.sql", "supabase/migrations/0002_uap_canonical.sql", "supabase/migrations/0003_uap_grant_epoch.sql"]
BASE = os.path.dirname(ROOT)
for p in ["uapcore/discovery.py", "uapcore/verify.py", "uapcore/carriers.py"]:
    s = open(os.path.join(BASE, p)).read(); assert "HIDDEN_TRUTH" not in s and "DISC" not in s, p
freeze = {"source": {p: sha(os.path.join(BASE, p)) for p in SRC}, "hidden_truth_sha256": sha(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH.json")), "at": time.time()}
json.dump(freeze, open(os.path.join(R, "FREEZE.json"), "w"), indent=2)

SEED = int.from_bytes(os.urandom(4), "big"); rng = random.Random(SEED); EPS = 0.05
SYN_KEY, VER_KEY = os.urandom(32), os.urandom(32)
st = Store(psycopg2.connect(dbname="uapinc", user="postgres", password="pg", host="127.0.0.1"))
st.q("insert into verify.keys values ('syn-uap','SYNTHESIZER'),('ver-uap','VERIFIER') on conflict do nothing")

def run_leg(name, carrier, window, negs, cls):
    sysid = st.system(name); roots = h(carrier.identity()); ep = st.epoch(sysid, 1, roots); port = st.port(sysid, ep)
    camp, run_id = st.campaign(sysid, cls, carrier.descent_level); log = {"leg": name, "run_id": run_id}
    try: st.stage(camp, "LIVE_PROBE"); log["unauthorized_stage"] = "ACCEPTED"
    except psycopg2.Error as e: log["unauthorized_stage"] = e.pgerror.split("\n")[0]
    st.stage(camp, "PASSIVE_WINDOW", "SHADOW")
    ins, outs, dom = inventory_from_window(window); bases = [q for q, _ in rng.sample(window, 8)]
    for kind, c in negs:
        st.bank(cls, kind, bank_nulls([(kind, c)], bases, ins, dom, rng))
    st.lock_threshold(cls, EPS)
    nulls = [float(x[0]) for x in st.cur.execute("select score from uap.negative_scores s join uap.negative_references r on r.id=s.reference_id where r.carrier_class=%s", (cls,)) or st.cur.fetchall()]
    st.stage(camp, "SHADOW", "BOUNDARY_PROBE"); st.stage(camp, "BOUNDARY_PROBE", "VERIFY")
    calls = {"n": 0}; orig = carrier.run
    def counted(x): calls["n"] += 1; return orig(x)
    carrier.run = counted
    synth = synthesize(carrier, window, rng, nulls, EPS)
    for c in synth["candidates"]: c["p_false_db"] = st.conformal_p(cls, c["score"])      # the database's own calculation
    st.affordances(camp, synth); st.stage(camp, "VERIFY")
    ver = verify(carrier, synth, rng.randrange(2**31)); carrier.run = orig
    live = sj(synth["decisions"]); settled, projections = [], []
    for r in ver:
        r["sig"] = sign(VER_KEY, {"c": r["consequence"], "v": r["constant_value"]})
        if r["constant_value"] is None: continue
        sid = st.settle(ep, r, live, check(VER_KEY, {"c": r["consequence"], "v": r["constant_value"]}, r["sig"]))
        projections.append(st.projection(ep, sid, r["consequence"], r["consequence"][4:] in synth["echo_like"])); settled.append(r["consequence"])
    try: st.ladder(port, "QUALIFIED"); log["ladder_skip"] = "ACCEPTED"
    except psycopg2.Error as e: log["ladder_skip"] = e.pgerror.split("\n")[0]
    if settled: st.ladder(port, "UNDERSTOOD")
    log.update({"system": str(sysid), "port": str(port), "epoch": str(ep), "settled": sorted(settled), "nondeterministic": synth["nondeterministic"],
                "twin": synth["twin"], "echo_like": synth["echo_like"], "silent_in_passive": synth["silent_in_passive"],
                "crossings": [{k: c[k] for k in ("output", "input", "factor")} for c in synth["crossings"]],
                "candidates": synth["candidates"], "n_nulls": len(nulls), "probe_calls": calls["n"],
                "ladder": st.q("select ladder_level from uap.ports where id=%s", (port,))[0],
                "delete_permitted": bool(projections) and st.q("select uap.grant_permitted(%s,%s,'DELETE')", (port, projections[0]))[0],
                "monitor_permitted": bool(projections) and st.q("select uap.grant_permitted(%s,%s,'MONITOR')", (port, projections[0]))[0],
                "projection_ids": [str(p) for p in projections], "decisions": synth["decisions"]})
    return log

legs = {}
# ---- API leg (v4.2) ----
srv = api_oms.serve(8766); time.sleep(0.3); base = "http://127.0.0.1:8766"
api = HttpCarrier(base, "/api/quote")
dom_api = {"qty": [1, 2, 3, 5, 8], "unit_price": [5.0, 12.5, 19.99, 40.0], "discount_code": ["NONE", "VIP", "STAFF", "PROMO5"],
           "region": ["CA", "TX", "OR", "NY"], "note": ["a", "b", "c"], "channel": ["WEB", "STORE"], "ts": [1700000000 + i for i in range(5)]}
traffic = [{k: rng.choice(v) for k, v in dom_api.items()} for _ in range(40)]
window = [(q, api.run(q)) for q in traffic]
legs["api"] = run_leg("LEGACY-OMS", api, window, [("CONSTANT", api.with_path("/neg/constant")), ("MASKING_CACHE", api.with_path("/neg/cache")),
                                                   ("CLIPPING_LIMITER", api.with_path("/neg/clip")), ("ECHO", api.with_path("/neg/echo"))], "api")
# ---- DB leg ----
erp = "dbname=legacy_erp user=postgres password=pg host=127.0.0.1"
db = SqlCarrier(erp, "quote_requests", "quote_view")
legs["db"] = run_leg("LEGACY-ERP", db, db.passive_window(40), [("CONSTANT", SqlCarrier(erp, "quote_requests", "neg_constant")),
                     ("CLIPPING_LIMITER", SqlCarrier(erp, "quote_requests", "neg_clip")), ("ECHO", SqlCarrier(erp, "quote_requests", "neg_echo"))], "db")
# ---- CLI leg ----
F = os.path.join(ROOT, "fixtures")
cli = CliCarrier([sys.executable, os.path.join(F, "legacy_rate.py")])
cwin = [(CliCarrier.parse_log_line(l), None) for l in open(os.path.join(F, "legacy_rate_invocations.log")).read().splitlines()]
cwin = [(q, cli.run(q)) for q, _ in cwin]
legs["cli"] = run_leg("RATE-TOOL", cli, cwin, [("CONSTANT", CliCarrier([sys.executable, os.path.join(F, "neg_constant.py")])),
                                               ("ECHO", CliCarrier([sys.executable, os.path.join(F, "neg_echo.py")]))], "cli")

# ---- DCA-UAP-02: semantic drift (v4.2 -> v4.3) and credential rotation ----
api_oms.STATE["version"] = "4.3"
drift = {"old_roots": None, "new_roots": h(api.identity())}
old = legs["api"]; sysid = old["system"]
drift["old_roots"] = st.q("select roots_hash from uap.port_epochs where id=%s", (old["epoch"],))[0]
drift["detected"] = drift["old_roots"] != drift["new_roots"]
ep2 = st.epoch(sysid, 2, drift["new_roots"]); port = st.port(sysid, ep2)
drift["ladder_after_epoch_change"] = st.q("select ladder_level from uap.ports where id=%s", (port,))[0]
drift["old_projection_monitor_after_drift"] = st.q("select uap.grant_permitted(%s,%s,'MONITOR')", (port, old["projection_ids"][0]))[0]
window2 = [(q, api.run(q)) for q in traffic]
camp, _ = st.campaign(sysid, "api", 1); st.stage(camp, "PASSIVE_WINDOW", "SHADOW")
synth2 = synthesize(api, window2, rng, [0.0] * 39, EPS); ver2 = verify(api, synth2, rng.randrange(2**31))
live2 = sj(synth2["decisions"]); settled2 = []
for r in ver2:
    if r["constant_value"] is None: continue
    s = sign(VER_KEY, {"c": r["consequence"], "v": r["constant_value"]})
    st.settle(ep2, r, live2, check(VER_KEY, {"c": r["consequence"], "v": r["constant_value"]}, s)); settled2.append(r["consequence"])
if settled2: st.ladder(port, "UNDERSTOOD")
drift.update({"settled_v4_3": sorted(settled2), "new": sorted(set(settled2) - set(old["settled"])),
              "gone": sorted(set(old["settled"]) - set(settled2)), "unchanged": sorted(set(old["settled"]) & set(settled2))})
st.q("insert into effect.fences values ('legacy-oms', 1, 'credential-2026-A')")
st.q("select effect.transfer_owner('legacy-oms','credential-2026-B')")
try: st.q("select effect.apply_once('legacy-oms',1,'act-old',%s,%s,'cert')", ("h", uuid.uuid4().hex)); drift["old_credential"] = "ACCEPTED"
except psycopg2.Error as e: drift["old_credential"] = e.pgerror.split("\n")[0]
srv.shutdown()

pred = {"seed": SEED, "legs": legs, "drift": drift}
json.dump(pred, open(os.path.join(R, "PREDICTIONS.json"), "w"), indent=2, default=str)
pred_hash = sha(os.path.join(R, "PREDICTIONS.json"))

# ---- open truth, score ----
T = json.load(open(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH.json")))
def deps(t): return {f"dep:{o}<-{i}" for o, ins in t.items() if not o.startswith("_") for i in ins}
score = {"predictions_sha256": pred_hash, "legs": {}}
for leg, key in (("api", "api_v4_2"), ("db", "db"), ("cli", "cli")):
    L = legs[leg]; truth = deps(T[key]); s = set(L["settled"])
    nd = T[key]["_nondeterministic"]
    g = {"zero_false_promotions": not (s - truth), "nondeterministic_caught": all(x in L["nondeterministic"] for x in nd),
         "echo_flagged": all(e in L["echo_like"] for e in T[key].get("_echo", [])), "unauthorized_stage_refused": "STAGE_NOT_AUTHORIZED" in L["unauthorized_stage"],
         "ladder_skip_refused": "LADDER_SKIP" in L["ladder_skip"], "ladder_understood": L["ladder"] == "UNDERSTOOD",
         "use_envelope_refuses_delete": L["delete_permitted"] is False and L["monitor_permitted"] is True,
         "twin_certified_cp": L["twin"]["certified"]}
    score["legs"][leg] = {"gates": g, "passed": sum(g.values()), "total": len(g), "recall": round(len(s & truth) / len(truth), 3),
                          "false_promotions": sorted(s - truth), "missed": sorted(truth - s), "probe_calls": L["probe_calls"]}
t43 = deps(T["api_v4_3"]); s2 = set(drift["settled_v4_3"])
g2 = {"drift_detected": drift["detected"], "ladder_reset_on_new_epoch": drift["ladder_after_epoch_change"] == "CONNECTED",
      "no_standing_carryover": drift["old_projection_monitor_after_drift"] is False, "zero_false_promotions_v4_3": not (s2 - t43),
      "new_dependency_channel_found": any(x.endswith("<-channel") for x in drift["new"]), "old_credential_refused": "STALE_OWNER" in drift["old_credential"]}
score["dca_uap_02"] = {"gates": g2, "passed": sum(g2.values()), "total": len(g2), "recall_v4_3": round(len(s2 & t43) / len(t43), 3),
                       "new": drift["new"], "gone": drift["gone"], "missed": sorted(t43 - s2)}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2)
print(json.dumps(score, indent=2))
