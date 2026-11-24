"""UAP increment 05: semantics layer (CADR-001, bridges, ICC-001, PIE-001, MCD-001). Custody-bound one-shot run."""
import hashlib, json, os, random, sys, time, uuid
import psycopg2
ROOT = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(ROOT)
sys.path.insert(0, BASE); sys.path.insert(0, os.path.join(ROOT, "fixtures")); sys.path.insert(0, "/home/claude/vault")
from uapcore.carriers import HttpCarrier, SqlCarrier, CliCarrier, h
from uapcore.semantics import infer_bridge, holdout_check, invariant_core, pie_envelope, minimal_distinction, apply, candidates
from uapcore.store import Store, sj
from densvault.core import Vault
import api_oms
R = os.path.join(BASE, "inc05_results"); os.makedirs(R, exist_ok=True)
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
SRC = ["uapcore/carriers.py", "uapcore/semantics.py", "uapcore/store.py", "inc05/run_inc05.py", "inc05/fixtures/canonical_reference_ledger.json",
       "supabase/migrations/0001_uap_safety_spine.sql", "supabase/migrations/0002_uap_canonical.sql", "supabase/migrations/0003_uap_grant_epoch.sql",
       "supabase/migrations/0004_uap_finality.sql", "supabase/migrations/0005_uap_semantics.sql"]
V = Vault(os.environ.get("VAULT_DIR", "/home/claude/demo/vault")); e = V.find_entry(os.environ["VAULT_RUN_ID"])
frozen = {f["path"]: f["sha256"] for f in V.manifest(e["manifest_sha256"])["files"]}
mm = [p for p in SRC if frozen.get(p) != sha(os.path.join(BASE, p))]
assert not mm and e["kind"] == "ORIGINAL_FREEZE", f"CUSTODY_MISMATCH {mm}"
# Upstream lineage: INC-04 projections must be the published INC-04 results, byte for byte
up = V.find_entry(os.environ["UPSTREAM_RUN_ID"]); upf = {f["path"]: f["sha256"] for f in V.manifest(up["manifest_sha256"])["files"]}
UP_PATH = "/home/claude/uap/inc04_results/PREDICTIONS.json"
assert upf.get("inc04_results/PREDICTIONS.json") == sha(UP_PATH), "UPSTREAM_LINEAGE_MISMATCH"
CUSTODY = {"source": {"run_id": e["run_id"], "root": e["merkle_root"], "kind": e["kind"]}, "upstream": {"run_id": up["run_id"], "root": up["merkle_root"]}}
for p in ["uapcore/semantics.py"]: assert "HIDDEN_TRUTH" not in open(os.path.join(BASE, p)).read()
json.dump({"custody": CUSTODY, "truth_sha256": sha(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH_SEMANTICS.json"))}, open(os.path.join(R, "FREEZE.json"), "w"), indent=2)
UP = json.load(open(UP_PATH))["legs"]
LEDGER = json.load(open(os.path.join(ROOT, "fixtures/canonical_reference_ledger.json")))

SEED = int.from_bytes(os.urandom(4), "big"); rng = random.Random(SEED)
st = Store(psycopg2.connect(dbname="uapinc5", user="postgres", password="pg", host="127.0.0.1"))
def err(f):
    try: f(); return "ACCEPTED"
    except psycopg2.Error as x: return x.pgerror.split("\n")[0]

# ---- CADR-001: access derivation ----
st.q("insert into uap.access_roots values ('cred-oms','ops',null),('cred-erp','ops',null),('host-cli','ops',null),('finance-ledger','finance',null)")
for ch, root in [("oms.quote", "cred-oms"), ("erp.quote_view", "cred-erp"), ("cli.rate", "host-cli"), ("finance.anchors", "finance-ledger")]:
    st.q("insert into uap.access_channels(channel_id,root_id) values (%s,%s)", (ch, root))
for ch, parents in [("oms.lookup", ["oms.quote"]), ("recon.oms_erp", ["oms.quote", "erp.quote_view"]), ("docs.v2", ["bulk.v2"]), ("bulk.v2", ["docs.v2"])]:
    st.q("insert into uap.access_channels(channel_id,parent_channels) values (%s,%s)", (ch, parents))
st.q("select uap.recompute_access()")
def closure():
    st.cur.execute("select channel_id from uap.access_channels where in_closure order by 1"); return [r[0] for r in st.cur.fetchall()]
cadr = {"closure": closure()}

# ---- carriers and canonical registry ----
srv = api_oms.serve(8769); time.sleep(0.3)
oms = HttpCarrier("http://127.0.0.1:8769", "/api/quote")
erp = SqlCarrier("dbname=legacy_erp5 user=postgres password=pg host=127.0.0.1", "quote_requests", "quote_view")
cli = CliCarrier([sys.executable, os.path.join(ROOT, "fixtures/legacy_rate.py")])
CAR = {"oms": oms, "erp": erp, "cli": cli}; NATIVE_CH = {"oms": "oms.quote", "erp": "erp.quote_view", "cli": "cli.rate"}
for name, kind, unit in [("order.amount_usd", "NUMERIC", "usd"), ("order.requires_approval", "BOOLEAN", None), ("order.tax_usd", "NUMERIC", "usd"),
                         ("shipment.cost_usd", "NUMERIC", "usd"), ("shipment.cost_cents", "NUMERIC", "cents"), ("shipment.transit_days", "INTEGER", "days")]:
    st.q("insert into sem.canonical_fields values (%s,%s,%s)", (name, kind, unit))
MAP = [("oms", "total", "order.amount_usd", "NUMERIC", "usd"), ("oms", "status", "order.requires_approval", "BOOLEAN", None),
       ("oms", "tax", "order.tax_usd", "NUMERIC", "usd"), ("erp", "line_total", "order.amount_usd", "NUMERIC", "usd"),
       ("erp", "needs_approval", "order.requires_approval", "BOOLEAN", None), ("erp", "shipping", "shipment.cost_usd", "NUMERIC", "usd"),
       ("cli", "rate", "shipment.cost_cents", "NUMERIC", "cents"), ("cli", "eta_days", "shipment.transit_days", "INTEGER", "days")]
epochs = {s: st.epoch(st.system(s.upper()), 1, h(CAR[s].identity())) for s in CAR}
LEG = {"oms": "api", "erp": "db", "cli": "cli"}

bridges, icc, canon_writes = {}, {}, {}
for sysn, nat, can, kind, unit in MAP:
    key = f"{sysn}.{nat}->{can}"
    anchors = [(CAR[sysn].run(r["inputs"])[nat], r[can]) for r in LEDGER[sysn] if can in r]
    domain = UP[LEG[sysn]]["domains"]; observed = [CAR[sysn].run({k: rng.choice(v) for k, v in domain.items()})[nat] for _ in range(12)]
    b = infer_bridge(kind, unit, observed, anchors)
    if not anchors: b["survivors"] = candidates(kind, observed)
    v = holdout_check(kind, unit, observed, anchors) if anchors else {"ok": None}
    if b["state"] in ("CANONICAL_EQUIVALENT", "RECOVERABLE_BY_MAP") and not v["ok"]: b["state"] = "DOMAIN_LOCAL_ONLY"; b["downgraded_by_verifier"] = True
    b["verifier"] = v; bridges[key] = b
    resolved = b["state"] in ("CANONICAL_EQUIVALENT", "RECOVERABLE_BY_MAP")
    st.q("""insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,transform,evidence_channel,anchor_count,surviving_transforms,native_channel)
            values (%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (epochs[sysn], nat, can, b["state"], json.dumps(b["survivors"][0]) if resolved else None,
            "finance.anchors" if anchors else None, b["anchor_count"], json.dumps(b["survivors"]), NATIVE_CH[sysn]))
    part = UP[LEG[sysn]]["partitions"].get(nat, {}).get("program"); mag = next((m for m in UP[LEG[sysn]]["magnitude"] if m["on"] == nat), None)
    icc[key] = invariant_core(kind, b["survivors"], part, mag)
    def write(sysn=sysn, nat=nat, can=can, b=b):
        val = CAR[sysn].run(LEDGER[sysn][0]["inputs"])[nat] if LEDGER[sysn] else observed[0]
        t = b["survivors"][0] if b["survivors"] else {"scale": 1.0}
        st.q("insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value) values (%s,%s,%s,%s)",
             (epochs[sysn], nat, can, json.dumps(apply(t, val))))
    canon_writes[key] = err(write)

# A bridge argued from the target's own documentation channel has no access standing
docs_attempt = err(lambda: st.q("""insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,evidence_channel,anchor_count,surviving_transforms,native_channel)
    values (%s,'total','order.amount_usd','CANONICAL_EQUIVALENT','docs.v2',3,'[{"scale":0.01}]','oms.quote')""", (epochs["oms"],)))

# ---- MCD-001: when does the same canonical signature lead to different consequences? ----
t_oms_amt = bridges["oms.total->order.amount_usd"]["survivors"][0]; t_erp_amt = bridges["erp.line_total->order.amount_usd"]["survivors"][0]
t_oms_ap = bridges["oms.status->order.requires_approval"]["survivors"][0]; t_erp_ap = bridges["erp.needs_approval->order.requires_approval"]["survivors"][0]
records = []
for qty in range(1, 80, 3):
    for price, sku in ((12.5, "A100"), (40.0, "B200")):
        o = oms.run({"qty": qty, "unit_price": price, "discount_code": "NONE", "region": "CA", "note": "a", "ts": 1700000000})
        d = erp.run({"sku": sku, "qty": qty, "promo_code": "NONE", "warehouse": "W1", "memo": "std", "operator": "ann"})
        for _ in range(3):
            records.append({"amount_usd": apply(t_oms_amt, o["total"]), "requires_approval": apply(t_oms_ap, o["status"]), "source_system": "OMS",
                            "has_discount": False, "weekday": rng.randrange(7)})
            records.append({"amount_usd": apply(t_erp_amt, d["line_total"]), "requires_approval": apply(t_erp_ap, d["needs_approval"]), "source_system": "ERP",
                            "has_discount": False, "weekday": rng.randrange(7)})
rng.shuffle(records); half = len(records) // 2
mcd_full = minimal_distinction(records[:half], ["amount_usd"], "requires_approval", ["source_system", "has_discount", "weekday"])
mcd_full_holdout = minimal_distinction(records[half:], ["amount_usd"] + (mcd_full["minimal_distinction"] or []), "requires_approval", [])
mcd_without = minimal_distinction(records[:half], ["amount_usd"], "requires_approval", ["has_discount", "weekday"])
for m, sig in ((mcd_full, ["amount_usd"]), (mcd_without, ["amount_usd"])):
    st.q("insert into sem.mcd_results(consequence,signature,conflicts_found,minimal_distinction,status) values (%s,%s,%s,%s,%s)",
         ("order.requires_approval", sig, m["conflicts_found"], m["minimal_distinction"], m["status"]))
mcd = {"with_source_system": mcd_full, "holdout_after_distinction": mcd_full_holdout, "without_source_system": mcd_without, "records": len(records)}

# ---- PIE-001 envelopes ----
pie = {}
def ordered(k): return "ORDERING" in icc[k]["core"]
pie["order.amount_usd"] = pie_envelope(bridges["oms.total->order.amount_usd"], bridges["erp.line_total->order.amount_usd"], ordered("oms.total->order.amount_usd"), ordered("erp.line_total->order.amount_usd"))
pie["order.requires_approval"] = pie_envelope(bridges["oms.status->order.requires_approval"], bridges["erp.needs_approval->order.requires_approval"], False, False,
                                              mcd_full if mcd_full_holdout["status"] == "NO_CONFLICT" else {"status": "NO_DISTINCTION_AVAILABLE"}, kind="BOOLEAN")
pie["shipment.cost"] = pie_envelope(bridges["erp.shipping->shipment.cost_usd"], bridges["cli.rate->shipment.cost_cents"], ordered("erp.shipping->shipment.cost_usd"), ordered("cli.rate->shipment.cost_cents"))
for f, (a, b) in {"order.amount_usd": ("OMS", "ERP"), "order.requires_approval": ("OMS", "ERP"), "shipment.cost": ("ERP", "CLI")}.items():
    st.q("insert into sem.pie_envelopes(canonical_field,system_a,system_b,allowed_ops,forbidden_ops,required_distinctions,basis) values (%s,%s,%s,%s,%s,%s,%s)",
         ("shipment.cost_usd" if f == "shipment.cost" else f, a, b, pie[f]["allowed"], pie[f]["forbidden"], pie[f]["required_distinctions"], json.dumps({"bridges": True})))

# ---- CADR revocation drill ----
st.q("update uap.access_roots set revoked_at = now() where root_id = 'cred-erp'"); st.q("select uap.recompute_access()")
cadr["closure_after_erp_revocation"] = closure()
cadr["erp_bridge_after_revocation"] = err(lambda: st.q("""insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,evidence_channel,anchor_count,surviving_transforms,native_channel)
    values (%s,'line_total','order.amount_usd','CANONICAL_EQUIVALENT','finance.anchors',6,'[{"scale":1.0}]','erp.quote_view')""", (epochs["erp"],)))
cadr["docs_bridge_attempt"] = docs_attempt
srv.shutdown()

pred = {"seed": SEED, "custody": CUSTODY, "bridges": bridges, "icc": icc, "canonical_writes": canon_writes, "mcd": mcd, "pie": pie, "cadr": cadr}
json.dump(pred, open(os.path.join(R, "PREDICTIONS.json"), "w"), indent=2, default=str); ph = sha(os.path.join(R, "PREDICTIONS.json"))

# ===== score =====
T = json.load(open(os.path.join(ROOT, "fixtures/HIDDEN_TRUTH_SEMANTICS.json")))
g = {}
g["bridge_states_exact"] = all(bridges[k]["state"] == v for k, v in T["bridges"].items())
g["transforms_exact"] = (bridges["cli.rate->shipment.cost_cents"]["survivors"][0].get("scale") == T["transforms"]["cli.rate->shipment.cost_cents"]
                         and bridges["oms.status->order.requires_approval"]["survivors"][0].get("map") == T["transforms"]["oms.status->order.requires_approval"])
g["contradictory_ledger_detected"] = bridges["oms.tax->order.tax_usd"]["state"] == "CONTRADICTORY"
g["canonical_writes_only_through_proven_bridges"] = all((canon_writes[k] == "ACCEPTED") == (v in ("CANONICAL_EQUIVALENT", "RECOVERABLE_BY_MAP")) for k, v in T["bridges"].items())
g["icc_core_correct"] = all(set(T["icc_must_include"][k]) <= set(icc[k]["core"]) and not (set(T["icc_must_exclude"][k]) & set(icc[k]["core"])) for k in T["icc_must_include"])
g["icc_requests_separating_evidence"] = all(icc[k]["separating_evidence"] is not None for k in T["icc_must_include"])
g["mcd_minimal_distinction"] = mcd_full["minimal_distinction"] == T["mcd"]["with_source_system"] and mcd_full_holdout["status"] == "NO_CONFLICT"
g["mcd_refuses_spurious_distinction"] = mcd_without["status"] == T["mcd"]["without_source_system"]
g["pie_correct"] = (set(T["pie"]["order.amount_usd"]["allowed"]) <= set(pie["order.amount_usd"]["allowed"])
                    and set(T["pie"]["order.requires_approval"]["forbidden"]) <= set(pie["order.requires_approval"]["forbidden"])
                    and pie["order.requires_approval"]["required_distinctions"] == T["pie"]["order.requires_approval"]["required_distinctions"]
                    and set(T["pie"]["shipment.cost"]["forbidden"]) <= set(pie["shipment.cost"]["forbidden"])
                    and set(T["pie"]["shipment.cost"]["allowed"]) <= set(pie["shipment.cost"]["allowed"]))
g["cadr_closure_exact"] = set(cadr["closure"]) == set(T["cadr"]["in_closure"])
g["cadr_revocation_propagates"] = not (set(T["cadr"]["after_erp_revocation_not_in_closure"]) & set(cadr["closure_after_erp_revocation"]))
g["docs_channel_cannot_ground_a_bridge"] = "WITHOUT_ACCESS_STANDING" in docs_attempt
g["revoked_native_channel_cannot_ground_a_bridge"] = "NATIVE_CHANNEL_WITHOUT_ACCESS_STANDING" in cadr["erp_bridge_after_revocation"]
score = {"predictions_sha256": ph, "custody": CUSTODY, "gates": g, "passed": sum(g.values()), "total": len(g),
         "bridges": {k: b["state"] for k, b in bridges.items()}, "icc": {k: {"core": v["core"], "not_core": v["not_core"]} for k, v in icc.items() if k in T["icc_must_include"]},
         "mcd": {k: (v if isinstance(v, int) else {"status": v["status"], "distinction": v["minimal_distinction"], "conflicts": v["conflicts_found"]}) for k, v in mcd.items()},
         "pie": pie, "cadr": cadr, "canonical_writes": canon_writes}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2, default=str); print(json.dumps(score, indent=1, default=str))
