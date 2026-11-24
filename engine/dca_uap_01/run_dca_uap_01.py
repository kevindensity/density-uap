"""DCA-UAP-01 (API leg) one-shot local run: freeze -> commit truth hash -> port -> verifier
-> Postgres spine -> fenced effect -> seal predictions -> open truth -> score."""
import hashlib, json, os, random, sys, time, uuid, urllib.request, http.client
import psycopg2
sys.path.insert(0, os.path.dirname(__file__))
from fixture import target_server as T            # used ONLY to start the server and inject the lost ACK
from port.pipeline import HttpCarrier, synthesize, sign as ssign
from verifier.verifier import verify, sign as vsign, check as vcheck

ROOT = os.path.dirname(os.path.abspath(__file__)); R = os.path.join(ROOT, "results")
def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def sj(o): return hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()

# 0. Freeze source and commit the hidden-truth hash before anything runs
src = ["port/pipeline.py", "verifier/verifier.py", "fixture/target_server.py", "run_dca_uap_01.py",
       "../supabase/migrations/0001_uap_safety_spine.sql"]
freeze = {p: sha(os.path.join(ROOT, p)) for p in src}
truth_hash = sha(os.path.join(ROOT, "fixture/HIDDEN_TRUTH.json"))
for p in ["port/pipeline.py", "verifier/verifier.py"]:          # static isolation check
    s = open(os.path.join(ROOT, p)).read()
    assert "HIDDEN_TRUTH" not in s and "target_server" not in s and "DISC" not in s, f"isolation breach in {p}"
json.dump({"source_freeze": freeze, "hidden_truth_sha256": truth_hash, "frozen_at": time.time()},
          open(os.path.join(R, "FREEZE.json"), "w"), indent=2)

# 1. Start the opaque target and generate natural traffic (the passive window)
srv = T.serve(8765); time.sleep(0.3); carrier = HttpCarrier("http://127.0.0.1:8765")
SEED = int.from_bytes(os.urandom(4), "big")
rng = random.Random(SEED)
dom = {"qty": [1, 2, 3, 5, 8, 30], "unit_price": [5.0, 12.5, 19.99, 40.0], "discount_code": ["NONE", "VIP", "STAFF", "PROMO5"],
       "region": ["CA", "TX", "OR", "NY"], "note": ["a", "b", "c"], "ts": [1700000000 + i for i in range(5)]}
traffic = [{k: rng.choice(v) for k, v in dom.items()} for _ in range(40)]

# 2. Synthesizer (port) and independent verifier with separate keys and seeds
SYN_KEY, VER_KEY = os.urandom(32), os.urandom(32)
synth = synthesize(carrier, traffic, seed=rng.randrange(2**31), eps=0.05)
docs = carrier.observe("/docs")                                  # recorded as a hint only
ver = verify(carrier, synth, seed=rng.randrange(2**31))
for r in ver: r["sig"] = vsign(VER_KEY, {k: r[k] for k in ("consequence", "constant_value")})

# 3. Write to the Postgres safety spine; the trigger decides what may settle
conn = psycopg2.connect(dbname="spine_run", user="postgres", password="pg", host="127.0.0.1"); conn.autocommit = True
cur = conn.cursor()
cur.execute("insert into core.systems(name) values ('LEGACY-OMS fixture') returning id"); sysid = cur.fetchone()[0]
cur.execute("insert into uap.port_epochs(system_id,epoch_no,roots_hash) values (%s,1,%s) returning id", (sysid, sj(synth["identity"])))
epoch = cur.fetchone()[0]
cur.execute("insert into verify.keys values ('syn-uap','SYNTHESIZER'),('ver-uap','VERIFIER') on conflict do nothing")
live = sj(synth["decisions"]); settled, refused = [], []
for r in ver:
    ok_sig = vcheck(VER_KEY, {k: r[k] for k in ("consequence", "constant_value")}, r["sig"])
    if r["constant_value"] is None: refused.append((r["consequence"], "VERIFIER_FOUND_NO_WITNESS")); continue
    cur.execute("""insert into verify.refinement_receipts(port_epoch_id,consequence_key,live_class_hash,constant_value,
                   verifier_key_id,synthesizer_key_id,signature_verified) values (%s,%s,%s,'true','ver-uap','syn-uap',%s) returning id""",
                (epoch, r["consequence"], live, ok_sig))
    rid = cur.fetchone()[0]
    try:
        cur.execute("""insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
                       values (%s,%s,'SETTLED_TRUE',%s,%s)""", (epoch, r["consequence"], live, rid)); settled.append(r["consequence"])
    except psycopg2.Error as e: refused.append((r["consequence"], e.pgerror.split("\n")[0]))
# Adversarial: synthesizer tries to settle a consequence on its own candidate list without a verifier
self_attempt = None
try:
    cur.execute("""insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash)
                   values (%s,'dep:status<-region','SETTLED_TRUE',%s)""", (epoch, live))
    self_attempt = "ACCEPTED"
except psycopg2.Error as e: self_attempt = e.pgerror.split("\n")[0]

# 4. One bounded action with independent finality through the receiver-side fence + outcome lookup
cur.execute("insert into effect.fences values ('legacy-oms',1,'executor-A')")
def post_order(ref):
    try: carrier.run("/api/orders", {"ref": ref, "qty": 1}, ); return "ACK"
    except Exception: return "NO_ACK"
def guarded_effect(ref):
    cur.execute("select effect.apply_once('legacy-oms',1,%s,%s,%s,'cert')", (ref, sj({"ref": ref}), uuid.uuid4().hex))
    T.DROP_NEXT_ACK["flag"] = True; ack = post_order(ref)            # effect lands, ACK lost; executor A "dies"
    cur.execute("select effect.transfer_owner('legacy-oms','executor-B')"); ep = cur.fetchone()[0]
    cur.execute("select effect.apply_once('legacy-oms',%s,%s,%s,%s,'cert')", (ep, ref, sj({"ref": ref}), uuid.uuid4().hex))
    outcome = cur.fetchone()[0]                                      # ALREADY_COMMITTED: do not resend blindly
    found = carrier.observe(f"/api/orders?ref={ref}")["found"]        # finality adapter: outcome lookup
    if not found: post_order(ref)                                    # only resend when lookup proves absence
    return {"first_ack": ack, "successor_fence": outcome, "lookup_found": found}
before = T.EFFECT_COUNT["n"]; g = guarded_effect("ord-guarded"); guarded_effects = T.EFFECT_COUNT["n"] - before
before = T.EFFECT_COUNT["n"]; T.DROP_NEXT_ACK["flag"] = True
naive = [post_order("ord-naive"), post_order("ord-naive")]; naive_effects = T.EFFECT_COUNT["n"] - before   # negative control

# 5. Seal predictions BEFORE opening the truth
pred = {"seed": SEED, "synth": {k: synth[k] for k in synth if k != "domains"}, "verifier_receipts": [{k: r[k] for k in ("consequence","constant_value")} for r in ver],
        "settled": sorted(settled), "refused": refused, "self_settle_attempt": self_attempt, "doc_hint": docs,
        "effect": {"guarded": g, "guarded_world_effects": guarded_effects, "naive_world_effects": naive_effects}}
json.dump(pred, open(os.path.join(R, "PREDICTIONS.json"), "w"), indent=2)
pred_hash = sha(os.path.join(R, "PREDICTIONS.json"))

# 6. Open the truth and score
truth = json.load(open(os.path.join(ROOT, "fixture/HIDDEN_TRUTH.json")))
assert sha(os.path.join(ROOT, "fixture/HIDDEN_TRUTH.json")) == truth_hash
true_deps = {f"dep:{o}<-{i}" for o, ins in truth["dependencies"].items() for i in ins}
settled_s = set(settled)
false_promos = sorted(settled_s - true_deps); recovered = sorted(settled_s & true_deps); missed = sorted(true_deps - settled_s)
gates = {
 "G1_ZERO_UNSUPPORTED_SEMANTIC_PROMOTIONS": len(false_promos) == 0,
 "G2_NONDETERMINISTIC_FIELD_NEVER_SETTLED": not any("request_id" in s for s in settled_s) and "request_id" in synth["nondeterministic"],
 "G3_FALSE_DOC_CLAIM_NOT_PROMOTED": "dep:status<-region" not in settled_s,
 "G4_TRUE_DEPENDENCY_DOC_DENIED_RECOVERED": "dep:total<-discount_code" in settled_s,
 "G5_SELF_SETTLEMENT_REFUSED": self_attempt != "ACCEPTED",
 "G6_GUARDED_EFFECT_EXACTLY_ONCE": guarded_effects == 1,
 "G7_NAIVE_NEGATIVE_CONTROL_DUPLICATES": naive_effects == 2,
 "G8_NUISANCE_INPUT_TS_NEVER_SETTLED": not any(s.endswith("<-ts") for s in settled_s),
 "G9_ECHO_FIELD_FLAGGED": "ref<-note" in synth["echo_like"],
}
score = {"predictions_sha256": pred_hash, "gates": gates, "passed": sum(gates.values()), "total": len(gates),
         "false_promotions": false_promos, "recovered": recovered, "missed_true_dependencies": missed,
         "recall": round(len(recovered) / len(true_deps), 3), "n_negative_nulls": synth["n_negative_nulls"]}
json.dump(score, open(os.path.join(R, "SCORE.json"), "w"), indent=2)
print(json.dumps(score, indent=2)); srv.shutdown()
