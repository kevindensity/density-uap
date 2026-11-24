"""UAP live probe run (Linux user uapd). Never touches an external service: every observation is requested from the
UAC probe service, which enforces the owner-signed scope and budget. Negative references are local stand-ins
(same carrier code, local endpoints), so the bank adds no load to the real services.
Usage: uap_probe_run.py httpbin|dns   -> prints JSON proposals (dependency + replicated witness) and the sealed capture."""
import json, random, socket, struct, sys, threading, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, "/opt/density/uap")
import uapcore.discovery as D
from uapcore.discovery import synthesize, bank_nulls, inventory_from_window, twin_gate, _changed
D.TWIN_SPAN_S = {"httpbin": 30.0, "dns": 60.0}[sys.argv[1]]     # replays span 30 s (HTTP) or 60 s (DNS TTLs tick each second)
from uapcore.probe_carriers import HttpbinCarrier, DnsCarrier

TARGET = sys.argv[1]; RUN = f"{TARGET}-{uuid.uuid4().hex[:10]}"; rng = random.Random(int.from_bytes(uuid.uuid4().bytes[:4], "big")); EPS = 0.05
LOCATOR = {"httpbin": "httpbin.org", "dns": "1.1.1.1:53"}[TARGET]
DOM = {"httpbin": {"kind": ["anything", "status", "cache"], "n": [200, 201, 204, 418], "q": ["alpha", "bravo", "charlie"], "h": ["h-one", "h-two", "h-three"]},
       "dns": {"qname": ["example.com", "cloudflare.com", "density.dev", "no-such-host-uac-probe.example.com"], "qtype": ["A", "AAAA", "MX", "TXT", "NS", "SOA"],
               "rd": ["on", "off"], "cd": ["on", "off"], "do": ["on", "off"]}}[TARGET]

class ViaUAC:
    """The engine's carrier: every run() is a request to UAC, never a direct call."""
    def __init__(self): self.calls = 0
    def identity(self): return {"scope": LOCATOR, "via": "uac probe service"}
    def run(self, q):
        self.calls += 1
        req = urllib.request.Request("http://127.0.0.1:8070/probe", data=json.dumps({"scope": LOCATOR, "run": RUN, "inputs": q}).encode(), method="POST", headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read())
        except urllib.error.HTTPError as e: raise RuntimeError(json.loads(e.read()))

# ---- local negative stand-ins: they ignore their inputs ----
def http_constant(port, status, cache):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(status); self.send_header("Cache-Control", cache); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
    s = ThreadingHTTPServer(("127.0.0.1", port), H); threading.Thread(target=s.serve_forever, daemon=True).start()
def dns_constant(port, flags, an):
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
        while True:
            q, a = s.recvfrom(4096); qid = q[:2]
            s.sendto(qid + struct.pack(">HHHHH", 0x8000 | flags, 0, 0, 0, 0), a)     # a bare header: echoes only the id
    threading.Thread(target=loop, daemon=True).start()
class Deterministic:
    def __init__(self, c, base): self.c = c; self.nondet, _ = twin_gate(c, base, sorted(c.run(base).keys()), n=12, span_s=0)
    def run(self, q): return {k: v for k, v in self.c.run(q).items() if k not in self.nondet}

carrier = ViaUAC()
window = [(q, carrier.run(q)) for q in [{k: rng.choice(v) for k, v in DOM.items()} for _ in range(40)]]       # survey (recorded as evidence)
if TARGET == "httpbin":
    http_constant(18081, 200, "no-store"); http_constant(18082, 418, "max-age=7")
    negs = [HttpbinCarrier("http://127.0.0.1:18081"), HttpbinCarrier("http://127.0.0.1:18082")]
else:
    dns_constant(15353, 0x0180, 0); dns_constant(15354, 0x0083, 0)
    negs = [DnsCarrier("127.0.0.1", 15353), DnsCarrier("127.0.0.1", 15354)]
negs = [("NEG", Deterministic(n, window[0][0])) for n in negs]
ins, outs, dom = inventory_from_window(window)
nulls = bank_nulls(negs, [q for q, _ in rng.sample(window, 8)], ins, dom, rng)
assert len(nulls) >= 19, f"NEGATIVE_BANK_TOO_SMALL {len(nulls)}"
synth = synthesize(carrier, window, rng, nulls, EPS)

# ---- replicated witness for each candidate: base vs switched, each observed three times ----
def witness(i, o):
    bases = [q for q, _ in window]; rng.shuffle(bases)
    for b in bases[:12]:
        y0 = carrier.run(b).get(o)
        for v in dom[i]:
            if v == b[i]: continue
            s = dict(b); s[i] = v
            if _changed(carrier.run(s).get(o), y0):
                ys_b = [carrier.run(b).get(o) for _ in range(3)]; ys_s = [carrier.run(s).get(o) for _ in range(3)]
                if len({json.dumps(x) for x in ys_b}) == 1 and len({json.dumps(x) for x in ys_s}) == 1 and ys_b[0] != ys_s[0]:
                    return {"base": b, "switch_value": v, "base_output": ys_b[0], "switched_output": ys_s[0]}
    return None
proposals, dropped = [], []
for c in synth["candidates"]:
    w = witness(c["input"], c["output"])
    (proposals.append({"output": c["output"], "input": c["input"], "p_false": c["p_false"], "witness": w}) if w else dropped.append(f"{c['output']}<-{c['input']}"))

req = urllib.request.Request("http://127.0.0.1:8070/seal", data=json.dumps({"run": RUN}).encode(), method="POST", headers={"content-type": "application/json"})
with urllib.request.urlopen(req, timeout=60) as r: sealed = json.loads(r.read())
print(json.dumps({"capture_digest": sealed["content_digest"], "run": RUN, "target": TARGET, "probe_calls": carrier.calls, "nulls": len(nulls), "nondeterministic": synth["nondeterministic"], "twin": synth["twin"],
                  "echo_like": synth["echo_like"], "proposals": proposals, "replication_dropped": dropped, "sealed": sealed}))
