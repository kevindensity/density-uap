"""UAC probe carriers for public services that exist to be queried. Each carrier turns one probe (a dict of inputs)
into one observation (a dict of outputs). They gather; they never interpret: meaning is UAP's job.

  HttpbinCarrier   level 1: plain HTTP to httpbin.org, a service built for testing HTTP clients
  DnsCarrier       level 5: raw DNS over UDP (RFC 1035 wire format, EDNS0 per RFC 6891) to a public resolver
"""
import json, random, socket, struct, urllib.error, urllib.request

UA = "density-uac/0.1 (passive-safe probing under an owner-signed scope)"

class HttpbinCarrier:
    carrier_class, descent_level = "api", 1
    def __init__(self, base="http://httpbin.org", timeout=20): self.base, self.timeout = base.rstrip("/"), timeout
    def identity(self): return {"base": self.base}
    def _url(self, q):
        k, n = q["kind"], int(q["n"])
        if k == "status": return f"{self.base}/status/{n}"
        if k == "cache": return f"{self.base}/cache/{n}"
        return f"{self.base}/anything?q={urllib.request.quote(str(q['q']))}"
    def run(self, q):
        req = urllib.request.Request(self._url(q), headers={"User-Agent": UA, "X-Probe": str(q["h"]), "Accept": "application/json"})
        try:
            r = urllib.request.urlopen(req, timeout=self.timeout); status, headers, body = r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, dict(e.headers), e.read()
        try: j = json.loads(body) if body else {}
        except Exception: j = {}
        hdrs = {k.lower(): v for k, v in headers.items()}
        jh = {k.lower(): v for k, v in (j.get("headers") or {}).items()} if isinstance(j, dict) else {}
        return {"status_code": int(status), "cache_control": hdrs.get("cache-control", ""),
                "echo_q": (j.get("args") or {}).get("q", "") if isinstance(j, dict) else "", "echo_header": jh.get("x-probe", "")}

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "NSEC3": 50, "OPT": 41}
TYPENAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

def dns_query(qid, qname, qtype, rd, cd, do):
    flags = (0x0100 if rd else 0) | (0x0010 if cd else 0)
    hdr = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1)
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.rstrip(".").split(".")) + b"\x00" + struct.pack(">HH", QTYPES[qtype], 1)
    opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0x00008000 if do else 0, 0)       # EDNS0, 1232-byte UDP size, DO bit
    return hdr + q + opt

def _name(msg, i):
    """Read a (possibly compressed) name; return (name, index after it)."""
    labels, jumped, end, hops = [], False, None, 0
    while True:
        n = msg[i]
        if n & 0xC0 == 0xC0:
            if not jumped: end = i + 2
            i = ((n & 0x3F) << 8) | msg[i + 1]; jumped = True; hops += 1
            if hops > 32: raise ValueError("compression loop")
            continue
        if n == 0: i += 1; break
        labels.append(msg[i + 1:i + 1 + n].decode(errors="replace")); i += 1 + n
    return ".".join(labels), (end if jumped else i)

def dns_parse(msg):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12]); i = 12
    for _ in range(qd): _, i = _name(msg, i); i += 4
    sections = []
    for count in (an, ns, ar):
        rrs = []
        for _ in range(count):
            _, i = _name(msg, i); t, cls, ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10]); i += 10 + rdlen
            rrs.append((t, ttl))
        sections.append(rrs)
    return {"id": qid, "flags": flags, "an": sections[0], "ns": sections[1], "ar": sections[2]}

class DnsCarrier:
    carrier_class, descent_level = "protocol", 5
    def __init__(self, server="1.1.1.1", port=53, timeout=4.0, retries=2):
        self.addr, self.timeout, self.retries = (server, port), timeout, retries
    def identity(self): return {"resolver": self.addr[0], "protocol": "DNS over UDP, RFC 1035 wire format with EDNS0"}
    def run(self, q):
        on = lambda k: q[k] == "on"
        for attempt in range(self.retries + 1):
            qid = random.randrange(65536); pkt = dns_query(qid, q["qname"], q["qtype"], on("rd"), on("cd"), on("do"))
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(self.timeout)
            try:
                s.sendto(pkt, self.addr); data, _ = s.recvfrom(4096)
            except socket.timeout:
                if attempt == self.retries: raise
                continue
            finally: s.close()
            r = dns_parse(data)
            if r["id"] != qid: continue                         # not our answer
            f = r["flags"]; bit = lambda m: "on" if f & m else "off"
            ttls = [ttl for t, ttl in r["an"] + r["ns"] if t != 41]
            return {"rcode": RCODES.get(f & 0xF, str(f & 0xF)), "aa": bit(0x0400), "tc": bit(0x0200), "rd_echo": bit(0x0100), "ra": bit(0x0080),
                    "ad": bit(0x0020), "cd_echo": bit(0x0010), "an_count": len(r["an"]), "ns_count": len(r["ns"]),
                    "answer_types": "+".join(sorted({TYPENAMES.get(t, str(t)) for t, _ in r["an"]})) or "-",
                    "min_ttl": min(ttls) if ttls else -1, "id_echo": r["id"]}
        raise RuntimeError("no matching DNS response")
