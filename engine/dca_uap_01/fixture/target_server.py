"""Opaque 'legacy order service' fixture for DCA-UAP-01 (API leg).
Hidden semantics live only here and in HIDDEN_TRUTH.json; the port never reads either.
Also serves a negative-reference bank of systems that fool discovery."""
import json, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DISC = {"NONE": 0.0, "VIP": 0.15, "STAFF": 0.30, "PROMO5": 0.05}
TAXR = {"CA": 0.0725, "TX": 0.0625, "OR": 0.0, "NY": 0.04}
ORDERS = {}
EFFECT_COUNT = {"n": 0}
CACHE = {}
LOCK = threading.Lock()
DROP_NEXT_ACK = {"flag": False}

def quote(q):
    qty, price = int(q["qty"]), float(q["unit_price"])
    total = round(qty * price * (1 - DISC.get(q["discount_code"], 0.0)), 2)
    tax = round(total * TAXR.get(q["region"], 0.0), 2)
    status = "HOLD" if total > 1000 else "OK"
    return {"total": total, "tax": tax, "status": status, "ref": q.get("note", ""),
            "request_id": uuid.uuid4().hex, "server": "LEGACY-OMS/4.2"}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/":
            return self._send(200, {"product": "LEGACY-OMS", "version": "4.2", "host": "fixture-01"})
        if self.path == "/docs":   # deliberately wrong documentation: a hint, never truth
            return self._send(200, {"total": "qty * unit_price (discount_code is informational only)",
                                    "status": "depends on region", "tax": "flat 5%"})
        if self.path.startswith("/api/orders?ref="):
            ref = self.path.split("=", 1)[1]
            with LOCK: return self._send(200, {"found": ref in ORDERS, "payload": ORDERS.get(ref)})
        return self._send(404, {})
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); q = json.loads(self.rfile.read(n) or b"{}")
        p = self.path
        if p == "/api/quote": return self._send(200, quote(q))
        if p == "/api/orders":   # legacy: no idempotency support at all
            with LOCK:
                EFFECT_COUNT["n"] += 1; ORDERS[q["ref"]] = q
                if DROP_NEXT_ACK["flag"]:
                    DROP_NEXT_ACK["flag"] = False
                    self.close_connection = True; return       # effect committed, ACK lost
            return self._send(201, {"created": q["ref"]})
        if p == "/neg/echo": return self._send(200, {k: q[k] for k in q})
        if p == "/neg/constant": return self._send(200, {"total": 42.0, "tax": 1.0, "status": "OK"})
        if p == "/neg/cache":
            with LOCK:
                if "v" not in CACHE: CACHE["v"] = {k: v for k, v in quote(q).items() if k != "request_id"}
                return self._send(200, CACHE["v"])
        if p == "/neg/clip":
            r = quote(q); return self._send(200, {"total": min(r["total"], 1.0), "tax": 0.0, "status": "OK"})
        return self._send(404, {})

def serve(port):
    s = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=s.serve_forever, daemon=True).start(); return s
