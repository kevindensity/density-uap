#!/usr/bin/env python3
"""Build-admission attestor (D12). Run as root on the build host:

    attest.py pair <p0d-binary> <owner-issuer-binary> <commit> [--sign]
    attest.py uapd <uapd-binary> <commit> [--sign]

It hashes each binary itself, starts the candidates itself, runs every check itself, and only then signs: the
evidence binds component@sha256 and the commit, and the database verifies it (gates.external_checks). It refuses to
sign unless the run used PG_SSLMODE=verify-full: evidence from an unverified connection can be printed for a harness
check but can never back an admission. Secrets reach the candidates through the environment, never the command line;
nothing secret is printed.
"""
import datetime, hashlib, json, os, socket, subprocess, sys, time, urllib.error, urllib.request, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_ID, KEY_FILE = "attestor-kernel-1", "/var/lib/attestor/key"
CA = "/etc/density/supabase-root-ca.pem"

def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()
def envfile(p): return dict(l.split("=", 1) for l in open(p).read().splitlines() if "=" in l)
def pgt(v):
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pgt(v[k]) for k in ks) + "}"
    if isinstance(v, list): return "[" + ", ".join(pgt(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)
def http(method, url, body=None):
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as x: return x.status, json.loads(x.read() or b"null")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"null")
    except Exception as e: return 0, {"error": str(e)[:120]}
def wait_port(port, secs=25):
    t = time.time()
    while time.time() - t < secs:
        try: socket.create_connection(("127.0.0.1", port), 0.5).close(); return True
        except OSError: time.sleep(0.3)
    return False
def lp(s): b = s.encode(); return len(b).to_bytes(8, "big") + b
def signing_input(g):
    return (b"CFP-SIGNING-INPUT/1" + lp(g["v"]) + lp(g["grant_id"]) + lp(g["audience"]) + lp(g["effect"]["kind"]) + lp(g["effect"]["table"])
            + lp(g["effect"]["pk"]) + lp(g["prestate"]["digest"]) + lp(g["history"]["head"]) + lp(g["authority_epoch"]) + lp(g["intent"])
            + lp(g["not_before"]) + lp(g["not_after"]) + lp(str(g["quorum"]["t"])))
def verifies(pub, msg, sig):
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), msg); return True
    except Exception: return False
def start(binary, user, env, logname):
    log = open(f"/tmp/attest-{logname}.log", "w")
    return subprocess.Popen([binary], user=user, env={"PATH": "/usr/bin:/bin", **env}, stdout=log, stderr=log), f"/tmp/attest-{logname}.log"

def pair(p0d_bin, own_bin, mode):
    checks = []
    def check(name, ok, detail): checks.append({"check_name": name, "passed": bool(ok), "detail": str(detail).encode("ascii", "replace").decode()[:180]})
    ke, ie = envfile("/var/lib/kernel/secrets/env"), envfile("/var/lib/issuer/secrets/env")
    tls = {"PG_SSLMODE": mode, "PG_CA_CERT": CA}
    own, own_log = start(own_bin, "issuer", {**ie, **tls, "LISTEN": "127.0.0.1:18081"}, "owner")
    p0d, p0d_log = start(p0d_bin, "kernel", {**ke, **tls, "LISTEN": "127.0.0.1:18080", "OWNER_ISSUER_ADDR": "127.0.0.1:18081"}, "p0d")
    procs = [own, p0d]
    try:
        up = wait_port(18081) and wait_port(18080)
        s, h = http("GET", "http://127.0.0.1:18080/v1/health")
        check("p0d.starts_and_is_healthy", up and s == 200 and h.get("status") == "ok", f"health {s} {h}")
        log = open(p0d_log).read()
        check("p0d.reports_tls_mode", f"database TLS mode {mode}" in log, f"mode {mode}")
        check("p0d.enrolment_matches_ledger", "matches its ledger enrolment" in log, "startup self-check")
        for label, extra in (("wrong_generation", {"ISSUER_ROOT_GEN": "99"}), ("wrong_key", {"P0D_KEY_SEED": os.urandom(32).hex()})):
            bad, bad_log = start(p0d_bin, "kernel", {**ke, **tls, **extra, "LISTEN": "127.0.0.1:18082", "OWNER_ISSUER_ADDR": "127.0.0.1:18081"}, label)
            try: code = bad.wait(25)
            except subprocess.TimeoutExpired: bad.kill(); code = "still running"
            check(f"p0d.refuses_{label}", code not in (0, "still running") and "ENROLMENT_MISMATCH" in open(bad_log).read(), f"exit {code}")
        _, kp = http("GET", "http://127.0.0.1:18080/v1/pubkey"); _, op = http("GET", "http://127.0.0.1:18081/v1/pubkey")
        check("pair.pubkeys_match_configuration", kp.get("pubkey") == ie.get("P0D_PUBKEY") and op.get("pubkey") == ke.get("OWNER_ISSUER_PUBKEY"),
              f"p0d {str(kp.get('pubkey'))[:8]} owner {str(op.get('pubkey'))[:8]}")
        req = {"audience": "pg://density-customer-sim/app", "effect": {"kind": "update", "table": "app.feature_flags", "pk": "demo-attest"},
               "prestate_digest": "0" * 64, "history_head": "0" * 64, "intent": "build-admission attestation (never presented to a fence)", "ttl_s": 60}
        s, d = http("POST", "http://127.0.0.1:18080/v1/grants", req); g = d.get("grant") or {}
        sigs = {x["issuer"]: x for x in g.get("signatures", [])}; m = signing_input(g) if g else b""
        gen = int(ke.get("ISSUER_ROOT_GEN", "1"))
        check("grant.issued_with_two_verifying_signatures", s == 200 and len(sigs) == 2 and verifies(kp.get("pubkey", ""), m, sigs.get("p0d", {}).get("sig", ""))
              and verifies(op.get("pubkey", ""), m, sigs.get("owner-policy", {}).get("sig", "")), f"status {s}, {len(sigs)} signatures")
        check("grant.carries_configured_root_gen", all(x.get("root_gen") == gen for x in sigs.values()) and sigs, f"root_gen {[x.get('root_gen') for x in sigs.values()]} want {gen}")
        s, d = http("POST", "http://127.0.0.1:18080/v1/grants", {**req, "audience": "pg://not-allowed/db"})
        check("grant.refuses_audience_not_allowed", s == 409 and "grant" not in d, f"{s} {d.get('reason')}")
        s, d = http("POST", "http://127.0.0.1:18080/v1/grants", {**req, "ttl_s": 100000})
        check("grant.refuses_overlong_ttl", s == 400 and d.get("reason") == "TTL_OUT_OF_RANGE", f"{s} {d.get('reason')}")
        s, d = http("POST", "http://127.0.0.1:18080/v1/events", {"event_kind": "nonsense"})
        check("events.refuses_malformed_submission", s == 409 and d.get("decision") == "REJECT", f"{s} {d.get('reason')}")
        unsigned = {**g, "signatures": []} if g else {}
        s, d = http("POST", "http://127.0.0.1:18081/v1/cosign", {"grant": unsigned})
        check("owner.refuses_grant_not_signed_by_kernel", s == 403 and d.get("reason") == "NOT_SIGNED_BY_KERNEL", f"{s} {d.get('reason')}")
        for label, f in (("p0d", p0d_log), ("owner", own_log)):
            t = open(f).read()
            check(f"{label}.log_has_no_secret", not any(v and len(v) > 12 and v in t for v in list(ke.values()) + list(ie.values()) if v not in (mode,)), "scanned for every secret value")
    finally:
        for p in procs: p.kill()
    return checks

def uapd(bin_, mode):
    checks = []
    def check(name, ok, detail): checks.append({"check_name": name, "passed": bool(ok), "detail": str(detail).encode("ascii", "replace").decode()[:180]})
    e = envfile("/var/lib/uapd/env")
    r = subprocess.run([bin_, "shadow"], user="uapd", env={"PATH": "/usr/bin:/bin", **e, "PG_SSLMODE": mode, "PG_CA_CERT": CA}, capture_output=True, text=True, timeout=120)
    try: out = json.loads(r.stdout)
    except Exception: out = {}
    check("uapd.shadow_run_recorded", r.returncode == 0 and out.get("decision") == "RECORDED", f"exit {r.returncode}")
    check("uapd.agrees_with_oracle_on_every_candidate", out.get("verdict") == "AGREE" and out.get("diverged") == 0, f"{out.get('agreed')}/{out.get('candidates')} agree")
    check("uapd.reports_tls_mode", mode in r.stderr or mode == "verify-full", f"mode {mode}")
    return checks

def evidence(component, binary, commit, checks, sign):
    subj = f"{component}@{sha(binary)}"
    at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = {"subject": subj, "commit": commit, "at": at, "key_id": KEY_ID, "checks": checks}
    if sign:
        k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(KEY_FILE).read().strip()))
        msg = f"DENSITY-GATE-EVIDENCE/1|{subj}|{commit}|{at}|" + hashlib.sha256(pgt(checks).encode()).hexdigest()
        ev["sig"] = k.sign(msg.encode()).hex()
    return ev

if __name__ == "__main__":
    a = [x for x in sys.argv[1:] if x != "--sign"]; sign = "--sign" in sys.argv
    mode = os.environ.get("ATTEST_PG_SSLMODE", "verify-full")
    if sign and mode != "verify-full": sys.exit("REFUSED: admission evidence is signed only for runs under PG_SSLMODE=verify-full")
    if sign and not os.path.exists(CA): sys.exit(f"REFUSED: {CA} is not installed")
    if a[0] == "pair":
        c = pair(a[1], a[2], mode)
        out = [evidence("p0d", a[1], a[3], c, sign), evidence("owner-issuer", a[2], a[3], c, sign)]
    elif a[0] == "uapd":
        out = [evidence("uapd", a[1], a[2], uapd(a[1], mode), sign)]
    else: sys.exit(__doc__)
    print(json.dumps(out))
