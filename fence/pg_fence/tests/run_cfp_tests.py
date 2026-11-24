"""End-to-end conformance tests for pg_fence (CFP/1) on a real PostgreSQL 16 cluster."""
import json, os, struct, subprocess, threading, time, uuid, datetime as dt
import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HOST, PORT = "/tmp", 5544
AUD = "pg://demo/billing"
def conn(db, autocommit=True): return psycopg.connect(host=HOST, port=PORT, user="postgres", dbname=db, autocommit=autocommit)
def raw(k): return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEYS = {n: Ed25519PrivateKey.generate() for n in ["p0d", "owner", "rogue", "recovery"]}

def lp(t): b = ("" if t is None else str(t)).encode(); return struct.pack(">Q", len(b)) + b
def signing_input(g):
    f = [g["v"], g["grant_id"], g["audience"], g["effect"]["kind"], g["effect"]["table"], g["effect"]["pk"],
         g["prestate"]["digest"], g["history"]["head"], g["authority_epoch"], g["intent"], g["not_before"], g["not_after"], str(g["quorum"]["t"])]
    return b"CFP-SIGNING-INPUT/1" + b"".join(lp(x) for x in f)
def revoke_input(target, epoch): return b"CFP-REVOKE/1" + lp(target) + lp(str(epoch))

def ledger_conn(db): return conn("fence_ledger") if db == "app_durable" else conn(db)
def ledger_tbl(db, t): return t if db == "app_durable" else f"fence_ledger.{t}"

def enroll(db):
    with ledger_conn(db) as c:
        c.execute(f"delete from {ledger_tbl(db,'issuers')}"); c.execute(f"delete from {ledger_tbl(db,'recovery')}")
        c.execute(f"delete from {ledger_tbl(db,'consumed')}"); c.execute(f"update {ledger_tbl(db,'state')} set authority_epoch = 1")
        for n in ["p0d", "owner"]:
            c.execute(f"insert into {ledger_tbl(db,'issuers')} values (%s,%s,1,'active')", (n, raw(KEYS[n])))
        c.execute(f"insert into {ledger_tbl(db,'recovery')} values (1,%s)", (raw(KEYS["recovery"]),))
    with conn(db) as c:
        c.execute("alter table public.invoices disable trigger cfp_guard"); c.execute("delete from public.invoices")
        c.execute("delete from fence.receipts")
        c.execute("insert into public.invoices values (4417, 120.00, 'open'), (4418, 75.50, 'open')")
        c.execute("alter table public.invoices enable always trigger cfp_guard")

def make_grant(db, kind, pk, signers=("p0d", "owner"), t=2, audience=AUD, epoch=None, prestate=None, head=None, ttl=300, nb_offset=-60):
    with conn(db) as c:
        pre = prestate or c.execute("select fence.row_digest('public.invoices', %s)", (str(pk),)).fetchone()[0]
        hd = head or c.execute("select fence.history_head('public.invoices', %s)", (str(pk),)).fetchone()[0]
        ep = epoch or c.execute(f"select authority_epoch from fence_ledger.state").fetchone()[0]
    now = dt.datetime.now(dt.timezone.utc)
    g = {"v": "cfp/1", "grant_id": str(uuid.uuid4()), "audience": audience,
         "effect": {"kind": kind, "table": "public.invoices", "pk": str(pk)},
         "prestate": {"scheme": "row-json-sha256/1", "digest": pre}, "history": {"head": hd},
         "authority_epoch": str(ep), "intent": "a" * 64,
         "not_before": (now + dt.timedelta(seconds=nb_offset)).isoformat(), "not_after": (now + dt.timedelta(seconds=ttl)).isoformat(),
         "quorum": {"t": t}, "signatures": []}
    m = signing_input(g)
    for s in signers:
        key = KEYS[s]; g["signatures"].append({"issuer": s, "root_gen": 1, "sig": key.sign(m).hex()})
    return g

def apply(db, g, sql, params=(), sleep_after_begin=0, replica=False):
    """Run fence.begin(grant) then the effect in one transaction. Returns 'OK' or the CFP error code."""
    try:
        with conn(db, autocommit=False) as c:
            if replica: c.execute("set session_replication_role = replica")
            if g is not None: c.execute("select fence.begin(%s::jsonb)", (json.dumps(g),))
            if sleep_after_begin: time.sleep(sleep_after_begin)
            c.execute(sql, params); c.commit()
        return "OK"
    except psycopg.Error as e:
        msg = (e.diag.message_primary or str(e)).split("\n")[0]
        return msg if msg.startswith("CFP_") else f"ERROR: {msg}"

def amount(db, pk):
    with conn(db) as c: return float(c.execute("select amount from public.invoices where id=%s", (pk,)).fetchone()[0])

R = []
def check(name, got, expected, note=""):
    ok = got == expected; R.append({"test": name, "expected": expected, "got": got, "pass": ok, "note": note}); return ok

def suite(db):
    enroll(db)
    U = "update public.invoices set amount = amount + 1 where id = %s"
    g = make_grant(db, "update", 4417); check(f"{db}: T01 valid grant applies", apply(db, g, U, (4417,)), "OK")
    with conn(db) as c: n = c.execute("select count(*) from fence.receipts").fetchone()[0]
    check(f"{db}: T01 receipt written atomically", n, 1)
    check(f"{db}: T02 write without grant refused", apply(db, None, U, (4417,)), "CFP_NO_GRANT")
    check(f"{db}: T03 replay refused", apply(db, g, U, (4417,)), "CFP_REPLAY")
    check(f"{db}: T04 wrong audience", apply(db, make_grant(db, "update", 4417, audience="pg://other/x"), U, (4417,)), "CFP_WRONG_AUDIENCE")
    g5 = make_grant(db, "update", 4417); apply(db, make_grant(db, "update", 4417), U, (4417,))   # row changes after g5 was decided
    check(f"{db}: T05 changed prestate refused", apply(db, g5, U, (4417,)), "CFP_PRESTATE_CHANGED")
    check(f"{db}: T06 history mismatch refused", apply(db, make_grant(db, "update", 4417, head="f" * 64), U, (4417,)), "CFP_HISTORY_MISMATCH")
    check(f"{db}: T07 quorum shortfall (one signer)", apply(db, make_grant(db, "update", 4417, signers=("p0d",)), U, (4417,)), "CFP_QUORUM")
    check(f"{db}: T08 grant claiming t=1", apply(db, make_grant(db, "update", 4417, t=1), U, (4417,)), "CFP_QUORUM_POLICY")
    check(f"{db}: T09 unenrolled rogue signer", apply(db, make_grant(db, "update", 4417, signers=("p0d", "rogue")), U, (4417,)), "CFP_QUORUM")
    gf = make_grant(db, "update", 4417); gf["signatures"][1]["sig"] = KEYS["rogue"].sign(signing_input(gf)).hex()
    check(f"{db}: T10 forged signature for an enrolled issuer", apply(db, gf, U, (4417,)), "CFP_QUORUM")
    gt = make_grant(db, "update", 4417); gt["effect"]["pk"] = "4418"   # tampered after signing
    check(f"{db}: T11 tampered grant", apply(db, gt, U, (4418,)), "CFP_QUORUM")
    check(f"{db}: T12 grant for one row used on another", apply(db, make_grant(db, "update", 4417), U, (4418,)), "CFP_EFFECT_MISMATCH")
    check(f"{db}: T13 update grant used for delete", apply(db, make_grant(db, "update", 4418), "delete from public.invoices where id = %s", (4418,)), "CFP_EFFECT_MISMATCH")
    before = (amount(db, 4417), amount(db, 4418))
    r14 = apply(db, make_grant(db, "update", 4417), "update public.invoices set amount = amount + 1 where id in (4417, 4418)")
    check(f"{db}: T14 second row in one grant refused", r14 in ("CFP_GRANT_ALREADY_APPLIED", "CFP_EFFECT_MISMATCH"), True, f"code {r14}; depends on row order")
    check(f"{db}: T14 neither row changed (statement aborted)", (amount(db, 4417), amount(db, 4418)), before)
    check(f"{db}: T15 expired budget", apply(db, make_grant(db, "update", 4417, ttl=-10, nb_offset=-120), U, (4417,)), "CFP_BUDGET_EXPIRED")
    check(f"{db}: T16 replica mode cannot bypass the guard", apply(db, None, U, (4417,), replica=True), "CFP_NO_GRANT")
    # Rollback: the grant is not consumed if the transaction aborts, and can then be used once.
    gr = make_grant(db, "update", 4417)
    try:
        with conn(db, autocommit=False) as c:
            c.execute("select fence.begin(%s::jsonb)", (json.dumps(gr),)); c.execute(U, (4417,)); c.rollback()
    except psycopg.Error as e: pass
    check(f"{db}: T17 rolled-back grant reusable once", apply(db, gr, U, (4417,)), "OK")
    check(f"{db}: T17 then consumed", apply(db, gr, U, (4417,)), "CFP_REPLAY")

def revocation_tests(db):
    enroll(db)
    U = "update public.invoices set amount = amount + 1 where id = %s"
    g = make_grant(db, "update", 4417)
    out = {}
    def a(): out["A"] = apply(db, g, U, (4417,), sleep_after_begin=2.0)
    def b():
        time.sleep(0.5); t0 = time.time()
        m = revoke_input("owner", 2)
        try:
            with conn(db) as c:
                c.execute("select fence.revoke_issuer('owner','p0d',%s,%s)", (KEYS["p0d"].sign(m).hex(), KEYS["recovery"].sign(m).hex()))
            out["B"] = "OK"
        except psycopg.Error as e: out["B"] = str(e).split("\n")[0]
        out["B_wait"] = round(time.time() - t0, 2)
    ta, tb = threading.Thread(target=a), threading.Thread(target=b); ta.start(); tb.start(); ta.join(); tb.join()
    check(f"{db}: T18 effect admitted before revocation commits", out["A"], "OK")
    check(f"{db}: T18 revocation waits for the in-flight effect", out["B"] == "OK" and out["B_wait"] >= 1.2, True, f"revocation waited {out['B_wait']} s")
    with conn(db) as c: ep = c.execute("select authority_epoch from fence_ledger.state").fetchone()[0]
    check(f"{db}: T18 epoch advanced", ep, 2)
    check(f"{db}: T19 old-epoch grant refused after revocation", apply(db, make_grant(db, "update", 4417, epoch=1), U, (4417,)), "CFP_STALE_EPOCH")
    check(f"{db}: T19 grant from revoked issuer refused at new epoch", apply(db, make_grant(db, "update", 4417), U, (4417,)), "CFP_QUORUM")
    m = revoke_input("p0d", 3)
    try:
        with conn(db) as c: c.execute("select fence.revoke_issuer('p0d','p0d',%s,%s)", (KEYS["p0d"].sign(m).hex(), KEYS["recovery"].sign(m).hex())); r = "OK"
    except psycopg.Error as e: r = str(e).split("\n")[0]
    check(f"{db}: T20 issuer cannot revoke itself", r, "CFP_SELF_REVOCATION")

def restore_drill(db, expect_replay, revoke=True):
    """Back up the application database, consume a grant and revoke an issuer, then restore the backup."""
    enroll(db)
    U = "update public.invoices set amount = amount + 1 where id = %s"
    g = make_grant(db, "update", 4417)
    dump = f"/tmp/{db}.dump"
    subprocess.run(["pg_dump", "-h", HOST, "-p", str(PORT), "-U", "postgres", "-Fc", "-f", dump, db], check=True)
    first = apply(db, g, U, (4417,))
    if revoke:
        m = revoke_input("owner", 2)
        with conn(db) as c: c.execute("select fence.revoke_issuer('owner','p0d',%s,%s)", (KEYS["p0d"].sign(m).hex(), KEYS["recovery"].sign(m).hex()))
    with conn("postgres") as c:
        c.execute(f"select pg_terminate_backend(pid) from pg_stat_activity where datname = '{db}' and pid <> pg_backend_pid()")
        c.execute(f"drop database {db}"); c.execute(f"create database {db}")
    subprocess.run(["pg_restore", "-h", HOST, "-p", str(PORT), "-U", "postgres", "-d", db, dump], check=True, capture_output=True)
    replay = apply(db, g, U, (4417,))
    label = ("durable ledger" if db == "app_durable" else "local ledger (negative control)") + (", grant consumed and issuer revoked" if revoke else ", grant consumed only")
    tag = "T21" if revoke else "T22"
    check(f"{db}: {tag} restore drill, first use", first, "OK")
    if expect_replay:
        check(f"{db}: {tag} replay after restore [{label}]", replay, "OK", "negative control: a ledger restored with the application resurrects the consumed grant")
    else:
        check(f"{db}: {tag} replay after restore [{label}]", replay, "CFP_STALE_EPOCH" if revoke else "CFP_REPLAY", "refused: the ledger was not rolled back")

def overhead(db, n=200):
    enroll(db)
    with conn(db) as c:
        c.execute("create table if not exists public.plain(id int primary key, amount numeric)"); c.execute("delete from public.plain"); c.execute("insert into public.plain values (1, 0)")
    grants = [make_grant(db, "update", 4417) for _ in range(1)]
    t_plain = []; t_fenced = []
    for i in range(n):
        with conn(db, autocommit=False) as c:
            t0 = time.perf_counter(); c.execute("update public.plain set amount = amount + 1 where id = 1"); c.commit(); t_plain.append(time.perf_counter() - t0)
    for i in range(n):
        g = make_grant(db, "update", 4417)
        with conn(db, autocommit=False) as c:
            t0 = time.perf_counter(); c.execute("select fence.begin(%s::jsonb)", (json.dumps(g),)); c.execute("update public.invoices set amount = amount + 1 where id = 4417"); c.commit(); t_fenced.append(time.perf_counter() - t0)
    med = lambda xs: sorted(xs)[len(xs) // 2] * 1000
    return {"db": db, "n": n, "plain_median_ms": round(med(t_plain), 3), "fenced_median_ms": round(med(t_fenced), 3)}

if __name__ == "__main__":
    for db in ["app_durable", "app_local"]: suite(db)
    revocation_tests("app_durable")
    restore_drill("app_durable", expect_replay=False, revoke=True)
    restore_drill("app_durable", expect_replay=False, revoke=False)
    restore_drill("app_local", expect_replay=True, revoke=True)
    restore_drill("app_local", expect_replay=True, revoke=False)
    perf = [overhead("app_durable"), overhead("app_local")]
    passed = sum(r["pass"] for r in R)
    report = {"total": len(R), "passed": passed, "results": R, "overhead": perf}
    json.dump(report, open("/home/claude/pg_fence/tests/cfp_report.json", "w"), indent=2)
    for r in R: print(("PASS " if r["pass"] else "FAIL ") + r["test"] + f"  -> {r['got']}" + (f"  ({r['note']})" if r["note"] else ""))
    print(f"\n{passed}/{len(R)} passed"); print(json.dumps(perf))
