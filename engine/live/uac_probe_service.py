"""UAC probe service (Linux user uacd, 127.0.0.1:8070). The only component allowed to touch external services.
Every probe is checked against the owner-signed scope (declared, kind 'probe', route permitted) and the budget
carried INSIDE the signed declaration (max probes per run, minimum interval). Every probe and its response is
kept; /seal stores them as a content-addressed capture body and asks the kernel to admit the capture."""
import hashlib, json, os, sys, threading, time, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import psycopg
sys.path.insert(0, "/opt/density/uap")
from uapcore.probe_carriers import HttpbinCarrier, DnsCarrier

DB = "host=aws-1-us-west-1.pooler.supabase.com port=5432 dbname=postgres sslmode=require user=uacd_login.rtkslhpxdcjoeqhucebp password=" + open("/var/lib/uacd/secrets/db_password").read().strip()
CARRIERS = {"probe.http": lambda: HttpbinCarrier("http://httpbin.org"), "probe.dns": lambda: DnsCarrier("1.1.1.1", 53)}
LOCK = threading.Lock(); RUNS = {}; LAST = {}; SCOPES = {}
SPOOL = "/var/lib/uacd/spool"; os.makedirs(SPOOL, exist_ok=True)      # every probe is on disk the moment it happens

def pg_jsonb_text(v):
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pg_jsonb_text(v[k]) for k in keys) + "}"
    if isinstance(v, list): return "[" + ", ".join(pg_jsonb_text(x) for x in v) + "]"
    if isinstance(v, bool): return "true" if v else "false"
    return json.dumps(v, ensure_ascii=False)

def scope(locator):
    if locator in SCOPES: return SCOPES[locator]
    with psycopg.connect(DB) as c:
        r = c.execute("""select s.stream_id::text, s.kind, s.routes, s.status, e.payload->'budget'
                           from uac.scopes s join p0.events e on e.stream_id = s.stream_id and e.revision = 1 where s.locator = %s""", (locator,)).fetchone()
    if not r: raise PermissionError("SCOPE_NOT_DECLARED")
    stream, kind, routes, status, budget = r
    if status != "DECLARED" or kind != "probe": raise PermissionError("SCOPE_NOT_A_DECLARED_PROBE_SCOPE")
    route = [x for x in routes if x in CARRIERS]
    if len(route) != 1: raise PermissionError("ROUTE_NOT_PERMITTED")
    SCOPES[locator] = {"stream": stream, "route": route[0], "budget": budget, "carrier": CARRIERS[route[0]]()}
    return SCOPES[locator]

def probe(locator, run, inputs):
    sc = scope(locator); b = sc["budget"]
    with LOCK:
        r = RUNS.setdefault(run, {"scope": locator, "probes": []})
        if r["scope"] != locator: raise PermissionError("RUN_BELONGS_TO_ANOTHER_SCOPE")
        if len(r["probes"]) >= b["max_probes_per_run"]: raise PermissionError("BUDGET_EXHAUSTED")
        wait = LAST.get(locator, 0) + b["min_interval_ms"] / 1000 - time.monotonic()
        if wait > 0: time.sleep(wait)
        LAST[locator] = time.monotonic()
        out = sc["carrier"].run(inputs)
        rec = {"i": inputs, "o": out, "n": len(r["probes"])}; r["probes"].append(rec)
        with open(f"{SPOOL}/{run}.jsonl", "a") as f: f.write(json.dumps({"scope": locator, **rec}) + "\n")
    return out

def seal(run):
    """Store the run's evidence and ask the kernel to admit it. The run is released only after both succeed;
    on any failure it stays in memory and on disk, and sealing can simply be retried."""
    r = RUNS.get(run)
    if r is None and os.path.exists(f"{SPOOL}/{run}.jsonl"):          # recover a run from its spool (e.g. after a restart)
        lines = [json.loads(l) for l in open(f"{SPOOL}/{run}.jsonl")]
        r = {"scope": lines[0]["scope"], "probes": [{k: v for k, v in x.items() if k != "scope"} for x in lines]}
    if r is None: raise PermissionError("UNKNOWN_RUN")
    sc = scope(r["scope"])
    body = {"scope": r["scope"], "route": sc["route"], "run": run, "carrier": sc["carrier"].identity(), "probes": r["probes"]}
    digest = hashlib.sha256(pg_jsonb_text(body).encode()).hexdigest()
    with psycopg.connect(DB, autocommit=True) as c:
        c.execute("insert into uac.capture_bodies (content_digest, body, size_bytes) values (%s, %s::jsonb, 0) on conflict (content_digest) do nothing", (digest, json.dumps(body)))
    with urllib.request.urlopen("http://127.0.0.1:8080/v1/health", timeout=10) as h: epoch = json.loads(h.read())["authority_epoch"]
    observed = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sub = {"event_id": str(uuid.uuid4()), "event_kind": "capture:(none)->RECORDED", "stream_id": str(uuid.uuid4()), "subject_type": "capture",
           "subject_id": f"{r['scope']}:{sc['route']}@{observed}", "authority_epoch": epoch, "expected_revision": "0",
           "payload": {"scope_stream": sc["stream"], "route": sc["route"], "observed_at": observed, "content_digest": digest, "summary": {"probes": len(r["probes"]), "run": run}}}
    req = urllib.request.Request("http://127.0.0.1:8080/v1/events", data=json.dumps(sub).encode(), method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as x: res = json.loads(x.read())
    except urllib.error.HTTPError as e: res = json.loads(e.read())
    if res.get("decision") in ("ACCEPT", "REPLAY"):
        RUNS.pop(run, None); os.replace(f"{SPOOL}/{run}.jsonl", f"{SPOOL}/{run}.sealed")
    return {"capture": res, "content_digest": digest, "probes": len(r["probes"])}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        try:
            b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            res = probe(b["scope"], b["run"], b["inputs"]) if self.path == "/probe" else seal(b["run"]) if self.path == "/seal" else None
            code, res = (200, res) if res is not None else (404, {"error": "not found"})
        except PermissionError as e: code, res = 403, {"refused": str(e)}
        except Exception as e: code, res = 502, {"error": type(e).__name__, "detail": str(e)[:200]}
        self.send_response(code); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(json.dumps(res).encode())

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8070), H).serve_forever()
