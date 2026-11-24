"""Seven-verb, science-free carriers. Each exposes the same observation surface: run(inputs) -> outputs."""
import json, hashlib, shlex, subprocess, urllib.request

def _norm(v):
    from decimal import Decimal
    return float(v) if isinstance(v, Decimal) else v

def h(o): return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()

class HttpCarrier:
    carrier_class, descent_level = "api", 1
    def __init__(self, base, path): self.base, self.path = base, path
    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=5) as resp: return json.loads(resp.read() or b"{}")
    def identity(self): return self._req("GET", "/")
    def run(self, inputs): return self._req("POST", self.path, inputs)
    def with_path(self, path): return HttpCarrier(self.base, path)

class SqlCarrier:
    """Legacy database. Inventory from the catalog; each probe inserts into the staging table, reads the view,
    then ROLLS BACK, so probing leaves no effect (a shadow by transaction)."""
    carrier_class, descent_level = "db", 2
    def __init__(self, dsn, staging, view, key="id"):
        import psycopg2; self.conn = psycopg2.connect(dsn); self.staging, self.view, self.key = staging, view, key
    def identity(self):
        c = self.conn.cursor(); c.execute("select current_database(), version()"); r = c.fetchone(); self.conn.rollback()
        return {"database": r[0], "server": r[1].split(",")[0]}
    def inventory(self):
        c = self.conn.cursor()
        q = "select column_name from information_schema.columns where table_name=%s order by ordinal_position"
        c.execute(q, (self.staging,)); ins = [r[0] for r in c.fetchall() if r[0] != self.key]
        c.execute(q, (self.view,)); outs = [r[0] for r in c.fetchall() if r[0] != self.key]; self.conn.rollback()
        return ins, outs
    def passive_window(self, n=40):
        ins, outs = self.inventory(); c = self.conn.cursor()
        c.execute(f"select s.{self.key}, {', '.join('s.'+i for i in ins)} from {self.staging} s order by s.{self.key} limit %s", (n,))
        rows = c.fetchall(); window = []
        for r in rows:
            c.execute(f"select {', '.join(outs)} from {self.view} where {self.key}=%s", (r[0],))
            o = c.fetchone(); window.append((dict(zip(ins, r[1:])), {k: _norm(v) for k, v in zip(outs, o)}))
        self.conn.rollback(); return window
    def run(self, inputs):
        ins, outs = self.inventory_cached(); c = self.conn.cursor(); cols = list(inputs)
        try:
            c.execute(f"insert into {self.staging} ({', '.join(cols)}) values ({', '.join(['%s']*len(cols))}) returning {self.key}",
                      [inputs[k] for k in cols])
            rid = c.fetchone()[0]
            c.execute(f"select {', '.join(outs)} from {self.view} where {self.key}=%s", (rid,))
            return {k: _norm(v) for k, v in zip(outs, c.fetchone())}
        finally: self.conn.rollback()
    def inventory_cached(self):
        if not hasattr(self, "_inv"): self._inv = self.inventory()
        return self._inv

class CliCarrier:
    """Legacy command-line tool. Inputs are flags; outputs are key=value lines on stdout."""
    carrier_class, descent_level = "cli", 3
    def __init__(self, argv0): self.argv0 = argv0
    def identity(self):
        r = subprocess.run(self.argv0 + ["--version"], capture_output=True, text=True, timeout=10)
        return {"version": r.stdout.strip()}
    def run(self, inputs):
        args = list(self.argv0)
        for k, v in inputs.items():
            if isinstance(v, bool): args.append(f"--{k}" if v else f"--no-{k}")
            else: args += [f"--{k}", str(v)]
        r = subprocess.run(args, capture_output=True, text=True, timeout=10)
        out = {}
        for line in r.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try: v = float(v) if "." in v else int(v)
                except ValueError: pass
                out[k.strip()] = v
        out["exit_code"] = r.returncode; return out
    @staticmethod
    def parse_log_line(line):
        toks = shlex.split(line)[1:]; d, i = {}, 0
        while i < len(toks):
            t = toks[i]
            if t.startswith("--no-"): d[t[5:]] = False; i += 1
            elif i + 1 < len(toks) and not toks[i+1].startswith("--"):
                v = toks[i+1]
                try: v = float(v) if "." in v else int(v)
                except ValueError: pass
                d[t[2:]] = v; i += 2
            else: d[t[2:]] = True; i += 1
        return d
