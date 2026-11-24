"""Effect gateway (Linux user gatewayd, 127.0.0.1:8060). The only component that releases an effect.
It decides nothing final: a release ends at an acknowledgement; only the observer (the root's readback, a different
identity over a different route) can record DID. Flow per request:
  owner standing policy (signature verified here) -> plan (prestate, history, exact intended result) -> two-signature grant
  from the kernel, re-checked here at release -> durable SENT in the ledger BEFORE acting -> fence admission and write in
  one transaction at the target."""
import datetime, hashlib, json, os, uuid, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import psycopg, psycopg.sql
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EMITTER = "gatewayd@mcp-density-kernel"
OWNER_PUB = "9aa6b00cc07e6ebf7edbcc961aa8059dfcc4b7c41370a2e550d0d4fa4ee095e2"
ISSUERS = {"p0d": "10b3f7311525cbe5f4395360a82ccc1609ca0ed4f13a7c1f4f6ecd29c1369463", "owner-policy": "3e48dc90787f3765288e8b5bbf1fbea433de060c7db9c5fb9e3475b6c01c2fbb"}
POLICIES = "/var/lib/gatewayd/policies"
def _dsn(user, pwfile): return "host={h} port=5432 dbname=postgres sslmode=require connect_timeout=10 user=" + user + " password=" + open(pwfile).read().strip()
DB = _dsn("gatewayd_ledger.mzglmdydfcoljrwleooq", "/var/lib/gatewayd/secrets/db_password")              # the ledger: SENT for every target
TARGETS = {   # audience -> how to reach that target and which table its fence protects
    "pg://density-ledger/sandbox": {"dsn": DB, "table": "sandbox.flags"},
    "pg://density-customer-sim/app": {"dsn": _dsn("gatewayd_customer.khpubdyfjhtdwryucbqn", "/var/lib/gatewayd/secrets/db_password_customer_sim"), "table": "app.feature_flags"},
}
HOSTS = ["aws-1-us-west-1.pooler.supabase.com", "aws-0-us-west-1.pooler.supabase.com"]

def connect(dsn=None):
    last = None
    for h in HOSTS:
        try: return psycopg.connect((dsn or DB).format(h=h))
        except Exception as e: last = e
    raise last

def pg_jsonb_text(v):
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pg_jsonb_text(v[k]) for k in keys) + "}"
    if isinstance(v, list): return "[" + ", ".join(pg_jsonb_text(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)
def lp(s): b = s.encode(); return len(b).to_bytes(8, "big") + b
def verify(pub_hex, msg, sig_hex):
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg); return True
    except Exception: return False

class Refused(Exception): pass

def check_policy(stream):
    """The owner's standing policy: a kernel event the owner signed. Verified here from its readable fields."""
    p = json.load(open(f"{POLICIES}/{stream}.json")); ev = p["event"]
    sub = {k: ev[k] for k in ("event_kind", "stream_id", "subject_type", "subject_id", "payload")}; sub["references"] = []
    identity = hashlib.sha256(pg_jsonb_text(sub).encode()).hexdigest()
    msg = b"P0-EVENT/1" + lp(ev["event_kind"]) + lp(ev["stream_id"]) + lp(identity)
    if ev["event_kind"] != "standing_policy:(none)->ACTIVE" or not verify(OWNER_PUB, msg, p["owner_sig"]): raise Refused("POLICY_SIGNATURE_INVALID")
    pl = ev["payload"]
    if datetime.datetime.fromisoformat(pl["expires_at"].replace("Z", "+00:00")) < datetime.datetime.now(datetime.timezone.utc): raise Refused("POLICY_EXPIRED")
    return pl

def cfp_signing_input(g):
    return (b"CFP-SIGNING-INPUT/1" + lp(g["v"]) + lp(g["grant_id"]) + lp(g["audience"]) + lp(g["effect"]["kind"]) + lp(g["effect"]["table"])
            + lp(g["effect"]["pk"]) + lp(g["prestate"]["digest"]) + lp(g["history"]["head"]) + lp(g["authority_epoch"]) + lp(g["intent"])
            + lp(g["not_before"]) + lp(g["not_after"]) + lp(str(g["quorum"]["t"])))

def effect(req):
    stream, key, value, simulate = req["policy"], req["key"], req["value"], req.get("simulate")
    pl = check_policy(stream)
    cap = pl["capability"]                                    # effect:<audience>:<table>:<key prefix>*
    prefix, table, keyglob = cap.rsplit(":", 2); aud = prefix[len("effect:"):] if prefix.startswith("effect:") else None
    tgt = TARGETS.get(aud)
    if tgt is None or table != tgt["table"] or not (keyglob.endswith("*") and key.startswith(keyglob[:-1])): raise Refused("OUTSIDE_POLICY_CAPABILITY")
    if not (key.isascii() and value.isascii()): raise Refused("NON_ASCII_NOT_SUPPORTED")
    with connect() as c:
        # authority reductions mirrored from the kernel (revocation, exhaustion) are checked at release, not only the owner's signature
        reduced = c.execute("select ledger.policy_reduction(%s)", (stream,)).fetchone()[0]
        if reduced: raise Refused("POLICY_REDUCED: " + reduced)
        used = c.execute("select count(*) from ledger.sent where request->>'policy' = %s", (stream,)).fetchone()[0]
    if used >= int(pl["max_uses"]): raise Refused("POLICY_EXHAUSTED")
    with connect(tgt["dsn"]) as c:
        pre = c.execute("select fence.row_digest(%s, %s)", (table, key)).fetchone()[0]
        head = c.execute("select fence.history_head(%s, %s)", (table, key)).fetchone()[0]
    if pre == "absent": raise Refused("TARGET_ROW_ABSENT: an update needs an existing row; no grant requested")
    intended = hashlib.sha256(json.dumps({"key": key, "value": value}, separators=(",", ":")).encode()).hexdigest()
    gr = urllib.request.Request("http://127.0.0.1:8080/v1/grants", method="POST", headers={"content-type": "application/json"},
        data=json.dumps({"audience": aud, "effect": {"kind": "update", "table": table, "pk": key}, "prestate_digest": pre,
                         "history_head": head, "intent": "poststate:" + intended, "ttl_s": 120}).encode())
    try:
        with urllib.request.urlopen(gr, timeout=30) as r: res = json.loads(r.read())
    except urllib.error.HTTPError as e: res = json.loads(e.read())
    if res.get("decision") != "ISSUED": raise Refused("GRANT_NOT_ISSUED: " + str(res.get("reason")))
    g = res["grant"]
    # re-check at release: both issuers' signatures and the window, here, independently of the kernel's word
    msg = cfp_signing_input(g); ok = {s["issuer"] for s in g["signatures"] if s["issuer"] in ISSUERS and verify(ISSUERS[s["issuer"]], msg, s["sig"])}
    if len(ok) < int(g["quorum"]["t"]): raise Refused("GRANT_SIGNATURES_INVALID")
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (datetime.datetime.fromisoformat(g["not_before"][:26] + "+00:00") <= now <= datetime.datetime.fromisoformat(g["not_after"][:26] + "+00:00")): raise Refused("GRANT_OUTSIDE_WINDOW")
    # the effect registry in the ledger decides whether this grant may stand for this effect (reference-kernel grant rule)
    effect_key = req.get("effect") or hashlib.sha256(f"{aud}|{table}|{key}|{intended}|{pre}".encode()).hexdigest()
    try:
        with connect() as c:
            c.execute("select ledger.register_grant(%s, %s::jsonb, %s)", (effect_key, json.dumps(g), bool(req.get("retry_allowed", False))))
            c.commit()
    except psycopg.Error as e:
        raise Refused("GRANT_NOT_REGISTERED: " + str(e).split("\n")[0][:120])
    plan = {"policy": stream, "key": key, "value": value, "intended_poststate": intended, "prestate": pre, "history": head, "effect": effect_key}
    plan_digest = hashlib.sha256(pg_jsonb_text(plan).encode()).hexdigest()
    with connect() as c:                                     # SENT is durable before anything touches the target
        c.execute("insert into ledger.sent (grant_id, plan_digest, emitter, target, request, sent_at) values (%s, %s, %s, %s, %s::jsonb, now())",
                  (g["grant_id"], plan_digest, EMITTER, aud, json.dumps(dict(plan, grant=g))))
        c.commit()
    if simulate == "crash_after_sent": return {"grant_id": g["grant_id"], "status": "SIMULATED_CRASH_AFTER_SENT"}
    try:
        with connect(tgt["dsn"]) as c:
            c.execute("select fence.begin(%s::jsonb)", (json.dumps(g),))
            schema, tname = table.split(".")
            n = c.execute(psycopg.sql.SQL("update {}.{} set value = %s where key = %s").format(psycopg.sql.Identifier(schema), psycopg.sql.Identifier(tname)), (value, key)).rowcount
            if n != 1: raise Refused("TARGET_ROW_MISSING")
            c.commit()
    except psycopg.Error as e:
        return {"grant_id": g["grant_id"], "status": "REFUSED_BY_FENCE", "reason": str(e).split("\n")[0][:120]}
    if simulate == "crash_after_commit": return {"grant_id": g["grant_id"], "status": "SIMULATED_CRASH_AFTER_COMMIT"}
    return {"grant_id": g["grant_id"], "status": "ACKED", "note": "acknowledged, not final: only the observer can record DID"}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        self.send_response(code); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(json.dumps(obj).encode())
    def do_GET(self): self._send(200, {"status": "ok", "emitter": EMITTER}) if self.path == "/health" else self._send(404, {})
    def do_POST(self):
        try:
            if self.path != "/effects": return self._send(404, {})
            self._send(200, effect(json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        except Refused as e: self._send(403, {"status": "REFUSED", "reason": str(e)})
        except FileNotFoundError: self._send(403, {"status": "REFUSED", "reason": "UNKNOWN_POLICY"})
        except Exception as e: self._send(502, {"status": "ERROR", "detail": f"{type(e).__name__}: {str(e)[:160]}"})

if __name__ == "__main__":
    os.makedirs(POLICIES, exist_ok=True)
    ThreadingHTTPServer(("127.0.0.1", 8060), H).serve_forever()
