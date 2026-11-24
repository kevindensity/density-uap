"""Carriers for descent levels 4-7. Each turns a system with no API into the same observation surface the
discovery engine already uses: identity(), passive_window(), run(inputs) -> outputs. Science-free: carriers
gather and frame evidence; they never decide what a field means (UAP does, the verifier settles).

  4 FileDropCarrier   request files in, result files out; probes only through a declared validation inbox
  5 WireCarrier       undocumented binary protocol; the message grammar is INFERRED from a passive capture
  6 ScreenCarrier     terminal-screen application; fields found by reading the blank form
  7 BehaviorCarrier   no output values at all; acceptance and timing are the only observables
"""
import glob, hashlib, os, re, socket, statistics, subprocess, time, uuid

def _num(v):
    try: return int(v) if re.fullmatch(r"-?\d+", v) else float(v) if re.fullmatch(r"-?\d+\.\d+", v) else v
    except Exception: return v

def _csv(text):
    lines = [l for l in text.strip().splitlines() if l.strip()]
    hdr = [h.strip() for h in lines[0].split(",")]; vals = [v.strip() for v in lines[1].split(",")]
    return {k: _num(v) for k, v in zip(hdr, vals)}

# ---------------------------------------------------------------- level 4
class FileDropCarrier:
    """Batch system that reads request files from an inbox and writes result files to an outbox.
    Probes go only to the declared validation inbox, which computes without posting; the carrier records the
    ledger digest before and after so 'probing left no effect' is checked, not assumed."""
    carrier_class, descent_level = "file", 4
    def __init__(self, root, timeout=5.0): self.root, self.timeout = root, timeout
    def identity(self): return {"banner": open(os.path.join(self.root, "README.TXT")).read().splitlines()[0]}
    def ledger_digest(self):
        p = os.path.join(self.root, "ledger.dat")
        return hashlib.sha256(open(p, "rb").read() if os.path.exists(p) else b"").hexdigest()
    def passive_window(self, n=40):
        """Pair archived requests with archived results by job id (no probing)."""
        out = []
        for req in sorted(glob.glob(os.path.join(self.root, "archive", "REQ-*.csv")))[:n]:
            job = os.path.basename(req)[4:-4]; res = os.path.join(self.root, "archive", f"RES-{job}.csv")
            if os.path.exists(res): out.append((_csv(open(req).read()), _csv(open(res).read())))
        return out
    def run(self, inputs):
        job = uuid.uuid4().hex[:12]; cols = list(inputs)
        tmp = os.path.join(self.root, "validate", f".REQ-{job}.tmp")
        with open(tmp, "w") as f: f.write(",".join(cols) + "\n" + ",".join(str(inputs[c]) for c in cols) + "\n")
        os.rename(tmp, os.path.join(self.root, "validate", f"REQ-{job}.csv"))      # atomic drop
        res = os.path.join(self.root, "validate_out", f"RES-{job}.csv"); t0 = time.time()
        while not os.path.exists(res):
            if time.time() - t0 > self.timeout: raise TimeoutError(f"no result for {job}")
            time.sleep(0.002)
        time.sleep(0.001); r = _csv(open(res).read()); os.remove(res); return r

# ---------------------------------------------------------------- level 5
def infer_tlv_grammar(frames, max_header=4):
    """Candidate grammars: a fixed header of h bytes, then type-length-value records with a 1-byte tag and a
    1- or 2-byte big-endian length. A grammar is consistent only if it parses EVERY captured frame exactly, the
    header is identical across frames, and every frame carries the same tag set. Returns all consistent grammars
    (more than one = ambiguous, and the carrier refuses) plus the number rejected."""
    consistent, rejected = [], 0
    for h in range(0, max_header + 1):
        for lw in (1, 2):
            ok, tagsets, headers = True, set(), set()
            for fr in frames:
                if len(fr) < h + 1 + lw: ok = False; break
                headers.add(fr[:h]); i, tags = h, []
                while i < len(fr):
                    if i + 1 + lw > len(fr): ok = False; break
                    tag = fr[i]; ln = int.from_bytes(fr[i + 1:i + 1 + lw], "big")
                    if ln == 0 or i + 1 + lw + ln > len(fr): ok = False; break
                    tags.append(tag); i += 1 + lw + ln
                if not ok: break
                if len(tags) != len(set(tags)): ok = False; break
                tagsets.add(tuple(tags))
            if ok and len(headers) == 1 and len(tagsets) == 1: consistent.append({"header": list(headers)[0], "len_width": lw, "tags": list(list(tagsets)[0])})
            else: rejected += 1
    return consistent, rejected

def _tlv_parse(fr, g):
    i, h, lw, out = len(g["header"]), len(g["header"]), g["len_width"], {}
    while i < len(fr):
        tag = fr[i]; ln = int.from_bytes(fr[i + 1:i + 1 + lw], "big"); out[tag] = fr[i + 1 + lw:i + 1 + lw + ln]; i += 1 + lw + ln
    return out

def _type_of(values):
    """Value typing from the capture: printable ASCII everywhere -> text; otherwise fixed-width big-endian unsigned."""
    if all(all(32 <= b < 127 for b in v) for v in values): return "text"
    return f"u{8 * len(values[0])}be" if len({len(v) for v in values}) == 1 else "bytes"

class WireCarrier:
    """Undocumented binary request/response protocol over TCP. From a passive capture (hex request/response
    pairs) it infers the grammar for each direction; if the grammar is not unique it refuses to probe.
    Native field names are the inferred tags (t1, r17, ...); meaning is left to UAP."""
    carrier_class, descent_level = "protocol", 5
    def __init__(self, host, port, capture_lines, grammar_from=None):
        """grammar_from: reuse the grammar inferred for another endpoint speaking the same protocol (used for
        negative references, whose uniform traffic is too little evidence to pin a grammar down on its own)."""
        self.addr = (host, port); pairs = [l.split() for l in capture_lines if l.startswith("REQ ")]
        self.req = [bytes.fromhex(p[1]) for p in pairs]; self.res = [bytes.fromhex(p[3]) for p in pairs]
        if grammar_from is not None:
            self.qg, self.rg, self.q_rej, self.r_rej = grammar_from.qg, grammar_from.rg, 0, 0
        else:
            self.qg, self.q_rej = infer_tlv_grammar(self.req); self.rg, self.r_rej = infer_tlv_grammar(self.res)
            if len(self.qg) != 1 or len(self.rg) != 1: raise ValueError(f"AMBIGUOUS_OR_NO_GRAMMAR: {len(self.qg)} request, {len(self.rg)} response")
            self.qg, self.rg = self.qg[0], self.rg[0]
        pq = [_tlv_parse(f, self.qg) for f in self.req]; pr = [_tlv_parse(f, self.rg) for f in self.res]
        self.qtypes = {t: _type_of([p[t] for p in pq]) for t in self.qg["tags"]}; self.rtypes = {t: _type_of([p[t] for p in pr]) for t in self.rg["tags"]}
        self.qwidth = {t: len(pq[0][t]) for t in self.qg["tags"]}
    def grammar_report(self):
        return {"request_header": self.qg["header"].hex(), "request_len_width": self.qg["len_width"], "request_fields": {f"t{t}": self.qtypes[t] for t in self.qg["tags"]},
                "response_header": self.rg["header"].hex(), "response_fields": {f"r{t}": self.rtypes[t] for t in self.rg["tags"]},
                "request_grammars_rejected": self.q_rej, "response_grammars_rejected": self.r_rej}
    def _dec(self, raw, typ): return raw.decode() if typ == "text" else int.from_bytes(raw, "big") if typ.startswith("u") else raw.hex()
    def _enc(self, tag, v):
        typ, lw = self.qtypes[tag], self.qg["len_width"]
        raw = str(v).encode() if typ == "text" else int(v).to_bytes(self.qwidth[tag], "big")
        return bytes([tag]) + len(raw).to_bytes(lw, "big") + raw
    def encode(self, inputs): return self.qg["header"] + b"".join(self._enc(t, inputs[f"t{t}"]) for t in self.qg["tags"])
    def decode_request(self, fr): return {f"t{t}": self._dec(v, self.qtypes[t]) for t, v in _tlv_parse(fr, self.qg).items()}
    def decode_response(self, fr): return {f"r{t}": self._dec(v, self.rtypes[t]) for t, v in _tlv_parse(fr, self.rg).items()}
    def roundtrip_ok(self): return all(self.encode(self.decode_request(f)) == f for f in self.req)
    def identity(self): return {"request_header": self.qg["header"].hex(), "response_header": self.rg["header"].hex()}
    def passive_window(self, n=40): return [(self.decode_request(q), self.decode_response(r)) for q, r in list(zip(self.req, self.res))[:n]]
    def run(self, inputs):
        s = socket.create_connection(self.addr, timeout=5); fr = self.encode(inputs); s.sendall(len(fr).to_bytes(2, "big") + fr)
        n = int.from_bytes(self._recv(s, 2), "big"); out = self.decode_response(self._recv(s, n)); s.close(); return out
    @staticmethod
    def _recv(s, n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c: raise ConnectionError("closed")
            b += c
        return b

# ---------------------------------------------------------------- level 6
_FIELD = re.compile(r"^\s*([A-Z][A-Z ]*[A-Z])\s*[:.]+\s*(.*?)\s*$")
class ScreenCarrier:
    """Terminal-screen application. Input fields are found by reading the blank form (labels followed by
    underscores), in screen order; a probe types values separated by TAB and presses ENTER; outputs are the
    labelled values on the final screen that are not input fields."""
    carrier_class, descent_level = "ui", 6
    def __init__(self, argv): self.argv = argv; self.fields = self._read_form()
    def _screens(self, keys):
        out = subprocess.run(self.argv, input=keys, capture_output=True, text=True, timeout=10).stdout
        return [s for s in out.split("\x1b[2J") if s.strip()]
    def _read_form(self):
        form = self._screens("")[0]; fields = []
        for line in form.splitlines():
            m = _FIELD.match(line)
            if m and re.fullmatch(r"_+", m.group(2)): fields.append(m.group(1))
        return fields
    def identity(self): return {"title": self._screens("")[0].strip().splitlines()[0].strip(), "fields": self.fields}
    def parse_screen(self, screen):
        out = {}
        for line in screen.splitlines():
            m = _FIELD.match(line)
            if m and m.group(1) not in self.fields and not re.fullmatch(r"_*", m.group(2)): out[m.group(1)] = _num(m.group(2))
        return out
    def passive_window(self, recording):
        """Operator session recording: lines 'KEYS <tab-separated values>' each followed by the final screen."""
        win = []
        for keys, screen in recording:
            vals = keys.rstrip("\n").split("\t"); win.append(({f: _num(v) for f, v in zip(self.fields, vals)}, self.parse_screen(screen)))
        return win
    def run(self, inputs): return self.parse_screen(self._screens("\t".join(str(inputs[f]) for f in self.fields) + "\n")[-1])

# ---------------------------------------------------------------- level 7
class BehaviorCarrier:
    """A system whose only observables are behaviour: whether a request is accepted, and how long it takes.
    Timing is noisy, so each probe is the median of k repeats, mapped to the nearest latency level learned from
    passive traffic (a new level is opened only when a measurement is far from all known ones). The raw median is
    also reported, so the twin gate can show that raw timing is not a deterministic output.
    Every claim built on these outputs is INFERRED from behaviour, never observed as a value."""
    carrier_class, descent_level = "behavior", 7
    def __init__(self, call, k=3, sep_ms=1.0): self.call, self.k, self.sep = call, k, sep_ms; self.levels = []
    def _measure(self, inputs):
        ts, acc = [], None
        for _ in range(self.k):
            t0 = time.perf_counter(); acc = self.call(inputs); ts.append((time.perf_counter() - t0) * 1000)
        return acc, statistics.median(ts)
    def _level(self, ms):
        if self.levels:
            i = min(range(len(self.levels)), key=lambda j: abs(self.levels[j] - ms))
            if abs(self.levels[i] - ms) <= self.sep: return i
        self.levels.append(ms); return len(self.levels) - 1
    def learn_levels(self, observed_ms):
        """Cluster passive latencies: sorted values split wherever the gap exceeds sep_ms."""
        xs = sorted(observed_ms); groups = [[xs[0]]]
        for x in xs[1:]:
            (groups[-1].append(x) if x - groups[-1][-1] <= self.sep else groups.append([x]))
        self.levels = [statistics.median(g) for g in groups]
    def identity(self): return {"observables": ["accepted", "latency_level", "raw_latency_ms"]}
    def run(self, inputs):
        acc, ms = self._measure(inputs)
        return {"accepted": acc, "latency_level": self._level(ms), "raw_latency_ms": round(ms, 3)}
    def window_from_traffic(self, traffic):
        self.learn_levels([ms for _, _, ms in traffic])
        return [(q, {"accepted": a, "latency_level": self._level(ms), "raw_latency_ms": round(ms, 3)}) for q, a, ms in traffic]
