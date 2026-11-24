"""Finality adapters and the exactly-once procedure: receiver-side fence (Density) + outcome lookup (the legacy system).
A lost acknowledgement is resolved by lookup, never by blind resend; if lookup is unavailable the outcome is UNCERTAIN_WITHHOLD."""
import json, os, subprocess, urllib.request, uuid, hashlib

def phash(p): return hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()

class HttpFinality:
    carrier_class = "api"
    def __init__(self, base): self.base = base
    def send(self, action_id, payload):
        body = json.dumps(dict(payload, ref=action_id)).encode()
        try:
            r = urllib.request.Request(self.base + "/api/orders", data=body, method="POST", headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(r, timeout=5) as resp: json.loads(resp.read()); return "ACK"
        except Exception: return "NO_ACK"
    def lookup(self, action_id):
        try:
            with urllib.request.urlopen(self.base + f"/api/orders?ref={action_id}", timeout=5) as resp: return json.loads(resp.read())["matches"]
        except Exception: return None

class SqlFinality:
    """Fault injection models the network: 'ack_lost' commits then loses the reply; 'crash_before' dies before commit."""
    carrier_class = "db"
    def __init__(self, dsn): self.dsn = dsn; self.fault = None; self.lookup_down = False
    def send(self, action_id, payload):
        import psycopg2
        fault, self.fault = self.fault, None
        conn = psycopg2.connect(self.dsn)
        try:
            c = conn.cursor(); c.execute("insert into orders(sku,qty,customer_ref) values (%s,%s,%s)", (payload["sku"], payload["qty"], action_id))
            if fault == "crash_before": conn.rollback(); return "NO_ACK"
            conn.commit()
            return "NO_ACK" if fault == "ack_lost" else "ACK"
        finally: conn.close()
    def lookup(self, action_id):
        if self.lookup_down: return None
        import psycopg2
        conn = psycopg2.connect(self.dsn)
        try: c = conn.cursor(); c.execute("select count(*) from orders where customer_ref=%s", (action_id,)); return c.fetchone()[0]
        finally: conn.close()

class CliFinality:
    carrier_class = "cli"
    def __init__(self, argv0, ledger): self.argv0, self.ledger = argv0, ledger; self.fault = None; self.lookup_down = False
    def send(self, action_id, payload):
        env = dict(os.environ, BOOK_LEDGER=self.ledger); fault, self.fault = self.fault, None
        if fault: env["BOOK_FAULT"] = fault
        r = subprocess.run(self.argv0 + ["--ref", action_id, "--weight", str(payload["weight"]), "--zone", payload["zone"]], capture_output=True, text=True, env=env)
        return "ACK" if r.returncode == 0 and f"booked={action_id}" in r.stdout else "NO_ACK"
    def lookup(self, action_id):
        env = dict(os.environ, BOOK_LEDGER=self.ledger)
        if self.lookup_down: env["QUERY_FAULT"] = "down"
        r = subprocess.run(self.argv0 + ["--query", action_id], capture_output=True, text=True, env=env)
        if r.returncode != 0: return None
        return int(r.stdout.strip().split("=")[1])

class ExactlyOnce:
    """Executor and successor sides of one fenced action against one destination."""
    def __init__(self, store, destination): self.st, self.dest = store, destination
    def epoch(self): return self.st.q("select owner_epoch from effect.fences where destination=%s", (self.dest,))[0]
    def execute(self, adapter, action_id, payload):
        self.st.q("select effect.apply_once(%s,%s,%s,%s,%s,'cert')", (self.dest, self.epoch(), action_id, phash(payload), uuid.uuid4().hex))
        ack = adapter.send(action_id, payload)
        if ack == "ACK": self._receipt(action_id, "FINAL_COMMITTED", {"ack": True})
        return ack
    def recover(self, adapter, action_id, payload, new_owner):
        """Successor: take ownership, confirm the intent at the fence, then decide by lookup."""
        ep = self.st.q("select effect.transfer_owner(%s,%s)", (self.dest, new_owner))[0]
        fence = self.st.q("select effect.apply_once(%s,%s,%s,%s,%s,'cert')", (self.dest, ep, action_id, phash(payload), uuid.uuid4().hex))[0]
        n = adapter.lookup(action_id)
        if n is None: out = "UNCERTAIN_WITHHOLD"
        elif n >= 1: out = "FINAL_COMMITTED_NO_RESEND"
        else:
            ack = adapter.send(action_id, payload); out = "FINAL_ABSENT_RESENT" if ack == "ACK" else "UNCERTAIN_WITHHOLD"
        self._receipt(action_id, out, {"fence": fence, "lookup": n}); return out
    def _receipt(self, action_id, outcome, ev):
        self.st.q("insert into effect.finality_receipts(action_id,outcome,evidence) values (%s,%s,%s)", (action_id, outcome, json.dumps(ev)))
