#!/usr/bin/env python3
# Rotation step 4: obtain a live grant from p0d (new keys), and forge the same grant with the OLD seeds (read here,
# used in memory only, never printed). Prints both grants; the old-key one must be refused by the fence.
import json, urllib.request, uuid, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def lp(s): b = s.encode(); return len(b).to_bytes(8, "big") + b
def signing_input(g):
    return (b"CFP-SIGNING-INPUT/1" + lp(g["v"]) + lp(g["grant_id"]) + lp(g["audience"]) + lp(g["effect"]["kind"]) + lp(g["effect"]["table"])
            + lp(g["effect"]["pk"]) + lp(g["prestate"]["digest"]) + lp(g["history"]["head"]) + lp(g["authority_epoch"]) + lp(g["intent"])
            + lp(g["not_before"]) + lp(g["not_after"]) + lp(str(g["quorum"]["t"])))
def old_seed(path, var):
    for l in open(path).read().splitlines():
        if l.startswith(var + "="): return bytes.fromhex(l.split("=", 1)[1])

pre = sys.argv[1]
req = {"audience": "pg://density-customer-sim/app", "effect": {"kind": "update", "table": "app.feature_flags", "pk": "demo-checkout-v2"},
       "prestate_digest": pre, "history_head": pre, "intent": "rotation proof (rolled back, never applied)", "ttl_s": 60}
r = urllib.request.Request("http://127.0.0.1:8080/v1/grants", data=json.dumps(req).encode(), method="POST", headers={"content-type": "application/json"})
new = json.loads(urllib.request.urlopen(r, timeout=30).read())["grant"]

old = json.loads(json.dumps(new)); old["grant_id"] = str(uuid.uuid4())
msg = signing_input(old)
keys = {"p0d": old_seed("/var/lib/kernel/secrets/env.old", "P0D_KEY_SEED"), "owner-policy": old_seed("/var/lib/issuer/secrets/env.old", "OWNER_KEY_SEED")}
old["signatures"] = [{"issuer": i, "root_gen": 1, "sig": Ed25519PrivateKey.from_private_bytes(keys[i]).sign(msg).hex()} for i in ("p0d", "owner-policy")]
print(json.dumps({"new": new, "old": old}))
