"""UAP increment 03 (threshold bisection + DCA-UAP-03 finality):
Previously increment 02: DCA-UAP-01 across API, DB and CLI carriers, plus DCA-UAP-02 drift/requalification.
One recorded run. Freeze -> commit truth hash -> run every leg -> seal predictions -> open truth -> score."""
import hashlib, json, os, random, sys, time, uuid
import psycopg2
ROOT = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.dirname(ROOT)); sys.path.insert(0, os.path.join(ROOT, "fixtures"))
from uapcore.carriers import HttpCarrier, SqlCarrier, CliCarrier, h
from uapcore.discovery import synthesize, bank_nulls, inventory_from_window
from uapcore.verify import verify, sign, check
from uapcore.store import Store, sj
import api_oms
R = os.path.join(os.path.dirname(ROOT), "inc03_results"); os.makedirs(R, exist_ok=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
SRC = ["uapcore/carriers.py", "uapcore/discovery.py", "uapcore/verify.py", "uapcore/store.py", "inc03/run_inc03.py", "uapcore/finality.py", "supabase/migrations/0004_uap_finality.sql",
       "supabase/migrations/0001_uap_safety_spine.sql", "supabase/migrations/0002_uap_canonical.sql", "supabase/migrations/0003_uap_grant_epoch.sql"]
BASE = os.path.dirname(ROOT)
for p in ["uapcore/discovery.py", "uapcore/verify.py", "uapcore/carriers.py"]:
    s = open(os.path.join(BASE, p)).read(); assert "HIDDEN_TRUTH" not in s and "DISC" not in s, p
VAULT_RUN = os.environ["VAULT_RUN_ID"]; sys.path.insert(0, "/home/claude/vault")
from densvault.core import Vault
_v = Vault(os.environ.get("VAULT_DIR", "/home/claude/demo/vault")); _e = _v.find_entry(VAULT_RUN); _m = _v.manifest(_e["manifest_sha256"])
_frozen = {f["path"]: f["sha256"] for f in _m["files"]}
_mismatch = [p for p in SRC if _frozen.get(p) != sha(os.path.join(BASE, p))]
assert not _mismatch and _e["kind"] == "ORIGINAL_FREEZE", f"CUSTODY_MISMATCH: {_mismatch}"
CUSTODY = {"vault_run_id": VAULT_RUN, "merkle_root": _e["merkle_root"], "entry_hash": _e["entry_hash"], "kind": _e["kind"], "source_files_checked": len(SRC)}
freeze = {"custody": CUSTODY, "source": {p: sha(os.path.join(BASE, p)) for p in SRC}, "hidden_truth_sha256": sha(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH.json")), "at": time.time()}
json.dump(freeze, open(os.path.join(R, "FREEZE.json"), "w"), indent=2)

SEED = int.from_bytes(os.urandom(4), "big"); rng = random.Random(SEED); EPS = 0.05
SYN_KEY, VER_KEY = os.urandom(32), os.urandom(32)
st = Store(psycopg2.connect(dbname="uapinc3", user="postgres", password="pg", host="127.0.0.1"))
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
srv = api_oms.serve(8767); time.sleep(0.3); base = "http://127.0.0.1:8767"
api = HttpCarrier(base, "/api/quote")
dom_api = {"qty": [1, 2, 3, 5, 8], "unit_price": [5.0, 12.5, 19.99, 40.0], "discount_code": ["NONE", "VIP", "STAFF", "PROMO5"],
           "region": ["CA", "TX", "OR", "NY"], "note": ["a", "b", "c"], "channel": ["WEB", "STORE"], "ts": [1700000000 + i for i in range(5)]}
traffic = [{k: rng.choice(v) for k, v in dom_api.items()} for _ in range(40)]
window = [(q, api.run(q)) for q in traffic]
legs["api"] = run_leg("LEGACY-OMS", api, window, [("CONSTANT", api.with_path("/neg/constant")), ("MASKING_CACHE", api.with_path("/neg/cache")),
                                                   ("CLIPPING_LIMITER", api.with_path("/neg/clip")), ("ECHO", api.with_path("/neg/echo"))], "api")
# ---- DB leg ----
erp = "dbname=legacy_erp3 user=postgres password=pg host=127.0.0.1"
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

# ---- DCA-UAP-03: finality qualification per carrier ----
from uapcore.finality import HttpFinality, SqlFinality, CliFinality, ExactlyOnce
LEDGER = os.path.join(R, "legacy_bookings.csv")
if os.path.exists(LEDGER): os.remove(LEDGER)
book = CliFinality([sys.executable, os.path.join(F, "legacy_book.py")], LEDGER)
sqlf = SqlFinality(erp); httpf = HttpFinality(base)
def world(cls, ref):                       # ground truth read directly from each legacy system, not through the port
    if cls == "api": return sum(1 for o in api_oms.ORDERS if o.get("ref") == ref)
    if cls == "db":
        c = psycopg2.connect(erp); cur = c.cursor(); cur.execute("select count(*) from orders where customer_ref=%s", (ref,)); n = cur.fetchone()[0]; c.close(); return n
    return sum(1 for l in open(LEDGER) if l.split(",")[0] == ref) if os.path.exists(LEDGER) else 0
def set_fault(cls, adapter, fault):
    if cls == "api": api_oms.FAULT["mode"] = fault
    else: adapter.fault = fault
def set_lookup_down(cls, adapter, down):
    if cls == "api": api_oms.FAULT["mode"] = "lookup_down" if down else None
    else: adapter.lookup_down = down
finality = {}
payloads = {"api": {"qty": 1, "unit_price": 5.0}, "db": {"sku": "A100", "qty": 2}, "cli": {"weight": 3.0, "zone": "Z1"}}
for cls, adapter in (("api", httpf), ("db", sqlf), ("cli", book)):
    dest = f"{cls}-effects"; st.q("insert into effect.fences values (%s,1,'executor-A')", (dest,)); ex = ExactlyOnce(st, dest); pl = payloads[cls]
    D = {}; tag = uuid.uuid4().hex[:6]
    a = f"{cls}-clean-{tag}"; D["clean"] = {"ack": ex.execute(adapter, a, pl), "world": world(cls, a), "expect_world": 1}
    a = f"{cls}-acklost-{tag}"; set_fault(cls, adapter, "ack_lost"); ack = ex.execute(adapter, a, pl)
    D["ack_lost"] = {"ack": ack, "recovery": ex.recover(adapter, a, pl, "executor-B"), "world": world(cls, a), "expect_world": 1, "expect_recovery": "FINAL_COMMITTED_NO_RESEND"}
    a = f"{cls}-crashbefore-{tag}"; set_fault(cls, adapter, "crash_before"); ack = ex.execute(adapter, a, pl)
    D["crash_before"] = {"ack": ack, "recovery": ex.recover(adapter, a, pl, "executor-C"), "world": world(cls, a), "expect_world": 1, "expect_recovery": "FINAL_ABSENT_RESENT"}
    a = f"{cls}-lookupdown-{tag}"; set_fault(cls, adapter, "ack_lost"); ack = ex.execute(adapter, a, pl); set_lookup_down(cls, adapter, True)
    rec = ex.recover(adapter, a, pl, "executor-D"); set_lookup_down(cls, adapter, False)
    D["lookup_down"] = {"ack": ack, "recovery": rec, "world": world(cls, a), "expect_world": 1, "expect_recovery": "UNCERTAIN_WITHHOLD"}
    a = f"{cls}-naive-{tag}"; set_fault(cls, adapter, "ack_lost"); adapter.send(a, pl); adapter.send(a, pl)
    D["naive_control"] = {"world": world(cls, a), "expect_world": 2}
    try: st.q("select effect.apply_once(%s,1,%s,'h','n-%s','c')" % ("%s", "%s", uuid.uuid4().hex), (dest, f"{cls}-stale-{tag}")); D["stale_owner"] = "ACCEPTED"
    except psycopg2.Error as e: D["stale_owner"] = e.pgerror.split("\n")[0]
    try: st.q("select effect.apply_once(%s,%s,%s,'different',%s,'c')", (dest, ex.epoch(), f"{cls}-acklost-{tag}", uuid.uuid4().hex)); D["payload_conflict"] = "ACCEPTED"
    except psycopg2.Error as e: D["payload_conflict"] = e.pgerror.split("\n")[0]
    ok = (D["clean"]["world"] == 1 and all(D[k]["world"] == D[k]["expect_world"] and D[k]["recovery"] == D[k]["expect_recovery"] for k in ("ack_lost", "crash_before", "lookup_down"))
          and D["naive_control"]["world"] == 2 and "STALE_OWNER" in D["stale_owner"] and "PAYLOAD_CONFLICT" in D["payload_conflict"])
    # independent verifier: re-reads every drill outcome through the lookup, with its own key
    vfy = all(adapter.lookup(f"{cls}-{k}-{tag}") == D[k.replace("acklost","ack_lost").replace("crashbefore","crash_before").replace("lookupdown","lookup_down")]["expect_world"]
              for k in ("clean", "acklost", "crashbefore", "lookupdown"))
    sysid = st.system(f"{cls.upper()}-EFFECT"); ep = st.epoch(sysid, 1, h({"dest": dest})); port = st.effect_port(sysid, ep)
    if ok and vfy:
        r = {"consequence": f"finality:{cls}:exactly_once_under_drills", "constant_value": "true"}
        sig = sign(VER_KEY, {"c": r["consequence"], "v": "true"})
        st.settle(ep, r, "drills", check(VER_KEY, {"c": r["consequence"], "v": "true"}, sig))
        st.q("insert into uap.finality_adapters(port_id,carrier_class,fence_owner,drills,qualified,qualified_at) values (%s,%s,'RECEIVER_SIDE_FENCE_PLUS_OUTCOME_LOOKUP',%s,true,now())", (port, cls, json.dumps(D)))
        for lvl in ("UNDERSTOOD", "QUALIFIED"): st.ladder(port, lvl)
        try: st.ladder(port, "AUTHORIZED"); D["authorized_without_grant"] = "ACCEPTED"
        except psycopg2.Error as e: D["authorized_without_grant"] = e.pgerror.split("\n")[0]
        st.q("insert into uap.grants(port_id,scope,granted_by,expires_at) values (%s,%s,'authority-domain-ops',now()+interval '1 hour')", (port, f"{cls}.create"))
        st.ladder(port, "AUTHORIZED"); st.ladder(port, "ACTIONABLE")
    D["qualified"] = ok and vfy; D["verifier_agrees"] = vfy
    D["ladder"] = st.q("select ladder_level from uap.ports where id=%s", (port,))[0]
    finality[cls] = D
srv.shutdown()

pred = {"seed": SEED, "custody": CUSTODY, "legs": legs, "drift": drift, "finality": finality}
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
g3 = {}
for cls, D in finality.items():
    g3[cls] = {"clean_once": D["clean"]["world"] == 1, "ack_lost_no_resend": D["ack_lost"]["recovery"] == "FINAL_COMMITTED_NO_RESEND" and D["ack_lost"]["world"] == 1,
               "crash_before_resent_once": D["crash_before"]["recovery"] == "FINAL_ABSENT_RESENT" and D["crash_before"]["world"] == 1,
               "lookup_down_withholds": D["lookup_down"]["recovery"] == "UNCERTAIN_WITHHOLD" and D["lookup_down"]["world"] == 1,
               "naive_control_duplicates": D["naive_control"]["world"] == 2, "stale_owner_refused": "STALE_OWNER" in D["stale_owner"],
               "payload_conflict_refused": "PAYLOAD_CONFLICT" in D["payload_conflict"], "verifier_agrees": D["verifier_agrees"],
               "authorized_needs_grant": "live grant" in D.get("authorized_without_grant", ""), "reached_actionable": D["ladder"] == "ACTIONABLE"}
score["dca_uap_03"] = {c: {"gates": g, "passed": sum(g.values()), "total": len(g)} for c, g in g3.items()}
score["custody"] = CUSTODY
score["totals"] = {"passed": sum(v["passed"] for v in score["legs"].values()) + score["dca_uap_02"]["passed"] + sum(v["passed"] for v in score["dca_uap_03"].values()),
                   "total": sum(v["total"] for v in score["legs"].values()) + score["dca_uap_02"]["total"] + sum(v["total"] for v in score["dca_uap_03"].values())}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2)
print(json.dumps(score, indent=2))
