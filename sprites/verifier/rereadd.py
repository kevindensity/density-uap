"""rereadd: the independent re-read route (Linux user rereadd on the verifier Sprite).
Different host (Fly, not the root's AWS), different DNS operator and protocol (Google 8.8.8.8 over raw UDP, own codec;
the original uses Cloudflare DNS over HTTPS), different IP-ownership provider (RIPEstat; the original uses Team Cymru),
web fetched from Fly. Shares no code with the original collector. Every body is signed with the enrolled REREAD key.
Usage: rereadd.py once | daily"""
import datetime, hashlib, json, os, random, re, socket, ssl, struct, sys, time, urllib.request
import psycopg
from cryptography.hazmat.primitives import serialization

SECRETS = "/var/lib/rereadd/secrets"
KEY = serialization.load_pem_private_key(open(f"{SECRETS}/reread_key.pem", "rb").read(), None)
PW = open(f"{SECRETS}/db_password").read().strip()
HOSTS = ["aws-1-us-west-1.pooler.supabase.com", "aws-0-us-west-1.pooler.supabase.com"]
ROUTE, RESOLVER = "reread.fly-verifier", ("8.8.8.8", 53)
UA = "density-reread/1.0 (independent re-read route; contact via density.dev)"

def pg_jsonb_text(v):
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pg_jsonb_text(v[k]) for k in keys) + "}"
    if isinstance(v, list): return "[" + ", ".join(pg_jsonb_text(x) for x in v) + "]"
    if isinstance(v, bool): return "true" if v else "false"
    return json.dumps(v, ensure_ascii=False)

# ---------- DNS over UDP (RFC 1035), EDNS0, TCP fallback when truncated ----------
QTYPE = {"A": 1, "NS": 2, "MX": 15, "TXT": 16}
def _name(msg, off, depth=0):
    labels = []
    while True:
        if depth > 20: raise ValueError("compression loop")
        n = msg[off]
        if n == 0: return ".".join(labels), off + 1
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
            rest, _ = _name(msg, ptr, depth + 1); labels.append(rest) if rest else None
            return ".".join(labels), off + 2
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace")); off += 1 + n
def _query(name, qtype):
    qid = random.randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1) + b"".join(bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00"
    q += struct.pack(">HH", QTYPE[qtype], 1) + b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)   # EDNS0 OPT, 4096-byte payload
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.sendto(q, RESOLVER); msg = s.recv(65535); s.close()
    if struct.unpack(">H", msg[:2])[0] != qid: raise ValueError("id mismatch")
    if msg[2] & 0x02:                                                                          # truncated: retry over TCP
        t = socket.create_connection(RESOLVER, timeout=8); t.sendall(struct.pack(">H", len(q)) + q)
        ln = struct.unpack(">H", t.recv(2))[0]; msg = b""
        while len(msg) < ln: msg += t.recv(ln - len(msg))
        t.close()
    return msg
def dns(name, qtype):
    msg = _query(name, qtype)
    qd, an = struct.unpack(">HH", msg[4:8]); off = 12
    for _ in range(qd): _, off = _name(msg, off); off += 4
    out = []
    for _ in range(an):
        _, off = _name(msg, off); t, _c, _ttl, rdl = struct.unpack(">HHIH", msg[off:off + 10]); off += 10; rd = msg[off:off + rdl]
        if t == QTYPE[qtype]:
            if qtype == "A": out.append(socket.inet_ntoa(rd))
            elif qtype == "NS": out.append(_name(msg, off)[0].lower())
            elif qtype == "MX": out.append(f"{struct.unpack('>H', rd[:2])[0]} {_name(msg, off + 2)[0].lower()}")
            elif qtype == "TXT":
                i, parts = 0, []
                while i < len(rd): parts.append(rd[i + 1:i + 1 + rd[i]].decode("utf-8", "replace")); i += 1 + rd[i]
                out.append("".join(parts))
        off += rdl
    return sorted(set(out))

def http_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=20) as r: return json.loads(r.read())

def reread(domain):
    body = {"domain": domain, "route": ROUTE, "resolver": "8.8.8.8 udp (own codec)", "ip_registry": "ripestat", "sources": {}}
    try:
        body["dns_ns"], body["dns_mx"], body["dns_txt"], body["dns_a"] = dns(domain, "NS"), dns(domain, "MX"), dns(domain, "TXT"), dns(domain, "A")
        body["www_a"] = dns("www." + domain, "A")          # the original collector looks up owners for apex and www addresses
        body["sources"]["dns"] = "ok"
    except Exception as e: body["sources"]["dns"] = f"failed: {type(e).__name__}"
    try:
        owners = []
        for ip in sorted(set(body.get("dns_a", [])) | set(body.get("www_a", [])))[:8]:
            d = http_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}&sourceapp=density-reread")
            for a in d.get("data", {}).get("asns", []): owners.append({"ip": ip, "as_name": str(a.get("holder", "")).lower(), "asn": str(a.get("asn"))})
        body["ip_owners"] = owners; body["sources"]["ip_registry"] = "ok"
    except Exception as e: body["sources"]["ip_registry"] = f"failed: {type(e).__name__}"
    try:
        req = urllib.request.Request(f"https://{domain}/", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
            html = r.read(2_000_000).decode("utf-8", "replace"); hdrs = r.headers
        body["web_header_names"] = sorted({k.lower() for k in hdrs.keys()})
        body["web_server"] = (hdrs.get("server") or "").lower()
        # same definition as the original collector (hosts in any src or href attribute), so the same claim is measured
        body["web_script_hosts"] = sorted({m.lower() for m in re.findall(r"(?:src|href)\s*=\s*[\"']?(?:https?:)?//([a-zA-Z0-9.-]+)", html)})
        # stricter evidence, recorded separately: hosts of <script src> only
        body["web_script_src_hosts"] = sorted({m.lower() for m in re.findall(r"<script[^>]+src=[\"'](?:https?:)?//([^/\"'?#]+)", html, re.I)})
        body["sources"]["web"] = "ok"
    except Exception as e: body["sources"]["web"] = f"failed: {type(e).__name__}"
    return body

def connect():
    last = None
    for h in HOSTS:
        try: return psycopg.connect(f"host={h} port=5432 dbname=postgres sslmode=require connect_timeout=10 user=rereadd_login.rtkslhpxdcjoeqhucebp password={PW}", autocommit=True)
        except Exception as e: last = e
    raise last

def run_once():
    out = []
    with connect() as c:
        for stream, locator in c.execute("select stream_id, locator from uac.scopes where kind = 'domain' and status = 'DECLARED' order by locator").fetchall():
            body = reread(locator)
            digest = hashlib.sha256(pg_jsonb_text(body).encode()).hexdigest()
            sig = KEY.sign(f"DENSITY-REREAD/1|{digest}".encode()).hex()
            observed = datetime.datetime.now(datetime.timezone.utc)
            try:
                c.execute("insert into uac.reread_captures (content_digest, scope_stream, route, body, key_id, sig, observed_at) values (%s, %s, %s, %s::jsonb, 'reread-1', %s, %s) on conflict do nothing",
                          (digest, stream, ROUTE, json.dumps(body), sig, observed))
                out.append({"domain": locator, "digest": digest[:16], "sources": body["sources"]})
            except Exception as e: out.append({"domain": locator, "refused": str(e).split("\n")[0][:120]})
    return out

if __name__ == "__main__":
    if sys.argv[1:] == ["once"]: print(json.dumps(run_once())); sys.exit(0)
    while True:                                                               # daily at 06:42 UTC
        now = datetime.datetime.now(datetime.timezone.utc); nxt = now.replace(hour=6, minute=42, second=0, microsecond=0)
        if nxt <= now: nxt += datetime.timedelta(days=1)
        time.sleep((nxt - now).total_seconds())
        try: print(json.dumps(run_once()), flush=True)
        except Exception as e: print(f"run failed: {e}", file=sys.stderr, flush=True)
