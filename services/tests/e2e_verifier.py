"""Local end-to-end test of verifierd with p0d and owner-issuer against the replica (TLS to Postgres)."""
import json, os, subprocess, time, uuid, urllib.request
import psycopg
BIN = "/home/claude/density-services/target/release"; PG = dict(host="/tmp", port=5544); R = []
def check(n, ok, d=""): R.append({"test": n, "pass": bool(ok), "detail": d}); print(("PASS " if ok else "FAIL ") + n + (f"  [{d}]" if d else ""), flush=True)
def keygen(b): return json.loads(subprocess.run([f"{BIN}/{b}", "keygen"], capture_output=True, text=True).stdout)
def http(m, url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=m, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"null")
def wait(url):
    for _ in range(60):
        try: urllib.request.urlopen(url, timeout=1); return
        except Exception: time.sleep(0.2)
kp, ko, kv = keygen("p0d"), keygen("owner-issuer"), keygen("verifierd"); VID = "verifier-" + uuid.uuid4().hex[:6]
with psycopg.connect(**PG, user="postgres", dbname="uap_root_replica", autocommit=True) as c:
    c.execute("insert into p0.keys (key_id, role, process, pubkey, administrator) values (%s,'VERIFIER','verifierd',%s,'local')", (VID, bytes.fromhex(kv["pubkey_hex_enrol"])))
procs = []
def start(b, env): p = subprocess.Popen([f"{BIN}/{b}"], env={**os.environ, **env}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); procs.append(p)
start("owner-issuer", {"OWNER_KEY_SEED": ko["seed_hex_store_as_secret"], "P0D_PUBKEY": kp["pubkey_hex_enrol"], "ALLOWED_AUDIENCES": "pg://uap/conformance", "LISTEN": "127.0.0.1:8081"})
start("p0d", {"PG_SSLMODE": "require", "DATABASE_URL": "host=127.0.0.1 port=5544 user=p0d password=p0d dbname=uap_root_replica sslmode=require", "P0D_KEY_SEED": kp["seed_hex_store_as_secret"], "OWNER_ISSUER_ADDR": "127.0.0.1:8081", "OWNER_ISSUER_PUBKEY": ko["pubkey_hex_enrol"], "LISTEN": "127.0.0.1:8080"})
start("verifierd", {"PG_SSLMODE": "require", "DATABASE_URL": "host=127.0.0.1 port=5544 user=verifierd password=verifierd dbname=uap_root_replica sslmode=require", "VERIFIER_KEY_SEED": kv["seed_hex_store_as_secret"], "VERIFIER_KEY_ID": VID, "LISTEN": "127.0.0.1:8090"})
for u in ("http://127.0.0.1:8080/v1/health", "http://127.0.0.1:8090/v1/health"): wait(u)
E1, E2, E3 = "a115b373-aa13-4072-8433-e72041074bde", "aaa0c41f-ceef-41af-9fea-58b92e3f5749", "00000000-0000-0000-0000-0000000000e1"
def propose(name, systems):
    st = str(uuid.uuid4()); s, d = http("POST", "http://127.0.0.1:8080/v1/events", {"event_id": str(uuid.uuid4()), "event_kind": "node:(none)->PROPOSED", "stream_id": st, "subject_type": "node", "subject_id": name, "payload": {"name": name + "-" + st[:6], "systems": systems}, "authority_epoch": "1", "expected_revision": "0"})
    return st, d["event_digest"]
def admit_sub(st, head, name): return {"event_id": str(uuid.uuid4()), "event_kind": "node:PROPOSED->ADMITTED", "stream_id": st, "subject_type": "node", "subject_id": name, "authority_epoch": "1", "expected_revision": "1", "expected_predecessor": head}
try:
    s, h = http("GET", "http://127.0.0.1:8090/v1/health"); check("verifierd healthy over TLS with its read-only role", s == 200, json.dumps(h))
    st, head = propose("estate", [E1, E2]); sub = admit_sub(st, head, "estate")
    s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": sub})
    ok = s == 200 and d["decision"] == "RECEIPT"; b = d.get("basis", {}).get("systems", [])
    check("receipt issued for a Node whose systems all have settled evidence", ok and [x["settled"] for x in b] == [17, 19] and [x["unresolved"] for x in b] == [8, 6], json.dumps(d)[:300])
    s2, d2 = http("POST", "http://127.0.0.1:8080/v1/events", {**sub, "receipts": [d["receipt"]]}); check("kernel admits the Node with the verifier's receipt", d2.get("decision") == "ACCEPT" and d2.get("state") == "ADMITTED", d2.get("reason", ""))
    s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": sub}); check("no second receipt once the Node is admitted", d.get("reason") == "NODE_NOT_IN_EXPECTED_STATE")
    st, head = propose("partial", [E1, E3]); s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": admit_sub(st, head, "partial")}); check("refused when a system has no settled evidence", d.get("reason") == "NO_SETTLED_EVIDENCE" and d["detail"]["system"] == E3)
    st, head = propose("ghost", [str(uuid.uuid4())]); s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": admit_sub(st, head, "ghost")}); check("refused for an unknown system", d.get("reason") == "SYSTEM_WITHOUT_PORT")
    st, head = propose("tamper", [E1]); sub = admit_sub(st, head, "tamper"); s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": sub})
    s2, d2 = http("POST", "http://127.0.0.1:8080/v1/events", {**sub, "payload": {"note": "altered after signing"}, "receipts": [d["receipt"]]}); check("kernel rejects a submission altered after its receipt was signed", d2.get("reason") == "GUARD_REJECTED")
    cs = str(uuid.uuid4()); s, d = http("POST", "http://127.0.0.1:8080/v1/events", {"event_id": str(uuid.uuid4()), "event_kind": "conformance:(none)->OPEN", "stream_id": cs, "subject_type": "conformance", "subject_id": "v-run", "payload": {"run": "v"}, "authority_epoch": "1", "expected_revision": "0"})
    csub = {"event_id": str(uuid.uuid4()), "event_kind": "conformance:OPEN->RECEIPTED", "stream_id": cs, "subject_type": "conformance", "subject_id": "v-run", "authority_epoch": "1", "expected_revision": "1", "expected_predecessor": d["event_digest"]}
    s, r = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": csub}); s2, d2 = http("POST", "http://127.0.0.1:8080/v1/events", {**csub, "receipts": [r["receipt"]]}); check("receipt-gated conformance step admitted", d2.get("decision") == "ACCEPT")
    s, d = http("POST", "http://127.0.0.1:8090/v1/receipts", {"submission": {"event_kind": "kernel:(none)->ACTIVE", "stream_id": str(uuid.uuid4())}}); check("unsupported event kinds are refused", d.get("reason") == "UNSUPPORTED_EVENT")
finally:
    for p in procs: p.terminate()
print(f"\n{sum(r['pass'] for r in R)}/{len(R)} passed")
