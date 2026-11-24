"""Source-isolation audit for verifierd (LCG lesson 8). Reads the source; executes nothing from it.
Usage: verifier_isolation_audit.py <expected binary sha256>  -> JSON {checks: [...], source_sha256, binary_sha256}"""
import hashlib, json, re, sys

SRC = "/home/sprite/density-services/crates/verifierd/src/main.rs"
BIN = "/opt/density/bin/verifierd"
src = open(SRC).read()

def body(fn_name):
    m = re.search(r"async fn " + fn_name + r"\b[^{]*\{", src)
    if not m: return None
    i, depth = m.end(), 1
    while depth and i < len(src):
        depth += {"{": 1, "}": -1}.get(src[i], 0); i += 1
    return src[m.end():i - 1]

checks = []
def gate(name, ok, detail): checks.append({"check_name": name, "passed": bool(ok), "detail": detail})

ev = body("evaluate_claim")
gate("verifier.evaluate_claim_exists", ev is not None, "blind evaluation function found" if ev else "missing")
if ev is not None:
    hits = [t for t in ("claim_submission", "kernel_receipts", "blind_commitments", "sub[", "expect_true", "requested") if t in ev]
    gate("verifier.evaluate_claim_isolated", not hits, "no forbidden references" if not hits else "references " + ", ".join(hits))
sw = body("sweep")
if sw is None:
    gate("verifier.sweep_exists", False, "missing")
else:
    e, c, s = sw.find("evaluate_claim("), sw.find("insert into verify.blind_commitments"), sw.find("uap.claim_submission")
    gate("verifier.sweep_evaluates_before_reading_submission", -1 < e < s, f"evaluate at {e}, submission read at {s}")
    gate("verifier.sweep_commits_before_reading_submission", -1 < c < s, f"commit at {c}, submission read at {s}")
    gate("verifier.sweep_has_no_other_submission_read", sw.count("claim_submission") == 1, f"{sw.count('claim_submission')} submission reads in sweep")
gate("verifier.no_compiler_code_dependency", "uapcore" not in src and "uap::" not in src, "no compiler modules referenced")
bsha = hashlib.sha256(open(BIN, "rb").read()).hexdigest()
expected = sys.argv[1] if len(sys.argv) > 1 else ""
gate("verifier.running_binary_is_the_admitted_candidate", bsha == expected, f"binary {bsha[:16]}, candidate {expected[:16]}")
print(json.dumps({"checks": checks, "source_sha256": hashlib.sha256(src.encode()).hexdigest(), "binary_sha256": bsha}))
