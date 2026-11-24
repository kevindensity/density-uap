"""Opaque legacy order service with a version switch (v4.2 -> v4.3) for drift tests, plus a negative bank."""
import json, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
STATE = {"version": "4.2"}
DISC = {"NONE": 0.0, "VIP": 0.15, "STAFF": 0.30, "PROMO5": 0.05}
def tax_rate(region):
    t = {"CA": 0.0725, "TX": 0.0625, "OR": 0.0, "NY": 0.04}
    if STATE["version"] == "4.3": t["OR"] = 0.03
    return t.get(region, 0.0)
def quote(q):
    qty, price = int(q["qty"]), float(q["unit_price"])
    total = qty * price * (1 - DISC.get(q["discount_code"], 0.0))
    if STATE["version"] == "4.3" and q.get("channel") == "WEB": total *= 0.95
    total = round(total, 2); tax = round(total * tax_rate(q["region"]), 2)
    return {"total": total, "tax": tax, "status": "HOLD" if total > 1000 else "OK", "ref": q.get("note", ""),
            "request_id": uuid.uuid4().hex, "server": f"LEGACY-OMS/{STATE['version']}"}
CACHE = {}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self._send({"product": "LEGACY-OMS", "version": STATE["version"]})
    def do_POST(self):
        q = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        p = self.path
        if p == "/api/quote": return self._send(quote(q))
        if p == "/neg/echo": return self._send(dict(q))
        if p == "/neg/constant": return self._send({"total": 42.0, "tax": 1.0, "status": "OK"})
        if p == "/neg/cache":
            CACHE.setdefault("v", {k: v for k, v in quote(q).items() if k != "request_id"}); return self._send(CACHE["v"])
        if p == "/neg/clip":
            r = quote(q); return self._send({"total": min(r["total"], 1.0), "tax": 0.0, "status": "OK"})
def serve(port):
    s = ThreadingHTTPServer(("127.0.0.1", port), H); threading.Thread(target=s.serve_forever, daemon=True).start(); return s
