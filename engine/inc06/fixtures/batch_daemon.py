"""Legacy batch invoicing daemon (opaque to the port). Reads request CSV files dropped in an inbox and writes result
CSV files. inbox/ posts to the ledger; validate/ computes without posting (the declared safe channel)."""
import os, threading, time, uuid
DISC = {"NONE": 1.0, "VIP": 0.9, "STAFF": 0.8}
def compute(q, mode="real"):
    if mode == "constant": return {"invoice_total": 10.0, "review": "N", "ref_out": "X"}
    if mode == "echo": return dict(q)
    tot = round(int(q["qty"]) * float(q["unit_price"]) * DISC.get(q["disc"], 1.0) + (50.0 if int(q["qty"]) > 100 else 0.0), 2)
    return {"invoice_total": tot, "review": "Y" if tot > 5000 else "N", "batch_no": uuid.uuid4().hex[:8], "ref_out": q["customer_ref"]}
def _read(p):
    l = [x for x in open(p).read().splitlines() if x.strip()]; return dict(zip(l[0].split(","), l[1].split(",")))
def _write(p, d):
    tmp = p + ".tmp"; open(tmp, "w").write(",".join(d) + "\n" + ",".join(str(v) for v in d.values()) + "\n"); os.rename(tmp, p)
def start(root, mode="real"):
    for d in ("inbox", "outbox", "validate", "validate_out", "archive"): os.makedirs(os.path.join(root, d), exist_ok=True)
    open(os.path.join(root, "README.TXT"), "w").write("INVOICE BATCH SYSTEM IBS-7 (1994)\nDrop REQ-<job>.csv in inbox/ or validate/.\n")
    stop = threading.Event()
    def loop():
        while not stop.is_set():
            for src, dst, post in (("validate", "validate_out", False), ("inbox", "outbox", True)):
                for f in sorted(os.listdir(os.path.join(root, src))):
                    if not (f.startswith("REQ-") and f.endswith(".csv")): continue
                    p = os.path.join(root, src, f); q = _read(p); r = compute(q, mode); os.remove(p)
                    _write(os.path.join(root, dst, "RES-" + f[4:]), r)
                    if post: open(os.path.join(root, "ledger.dat"), "a").write(f"{f[4:-4]},{r.get('invoice_total')}\n")
            time.sleep(0.002)
    threading.Thread(target=loop, daemon=True).start(); return stop
def seed_archive(root, rng, n=40):
    dom = {"qty": [1, 2, 4, 6, 8], "unit_price": [12.5, 20.0, 35.0, 40.0], "disc": ["NONE", "VIP", "STAFF"], "customer_ref": ["acme", "bolt", "core", "delta"], "warehouse": ["W1", "W2", "W3"]}
    for k in range(n):
        q = {c: rng.choice(v) for c, v in dom.items()}; job = f"H{k:04d}"
        _write(os.path.join(root, "archive", f"REQ-{job}.csv"), q); _write(os.path.join(root, "archive", f"RES-{job}.csv"), compute(q))
