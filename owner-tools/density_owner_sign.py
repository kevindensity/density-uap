#!/usr/bin/env python3
"""Density owner signing: run on YOUR OWN machine (not on a server).

What it does:
  1. Creates your Density owner key the first time (Ed25519), stored encrypted with a passphrase you choose
     at ~/.density/owner_key.pem (readable only by you). Later runs reuse it.
  2. For each of the six actions below, rebuilds the exact submission from the readable fields, recomputes its
     identity digest and signing message itself, and refuses to sign if either differs from what the kernel
     reported. You are signing what the readable fields say, verified independently.
  3. Prints ONLY your public key and the six signatures. Send that output back; never send the key file.

Requires Python 3.8+ and the `cryptography` package (pip install cryptography).
"""
import getpass, hashlib, json, os, stat, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ACTIONS = [
  ("Withdraw stale proposal: p0d build 3af400e2…", "secure_boot:PROPOSED->WITHDRAWN", "7a66518b-8dbb-4af3-bbdb-4fb888d4ca3f", "p0d",
   {"decision": "withdraw", "artifact_digest": "3af400e282159e2f8c076d40fdb660e404ed2a5002afae5963d64b76aa9927ff", "reason": "superseded by the running rebuild"},
   "b8da9382c8ec051349804f91c897ae5c1bc1f0923bd24f880cb1989fc21e525c"),
  ("Withdraw stale proposal: owner-issuer build f20c2558…", "secure_boot:PROPOSED->WITHDRAWN", "0638a90d-45b7-44e1-b8ce-84e28ce259fa", "owner-issuer",
   {"decision": "withdraw", "artifact_digest": "f20c2558784f0d4e2c1b00d20d2918ccc9aaccf9c069dbcb54426ffa634027cf", "reason": "superseded by the running rebuild"},
   "8c572ece1fdd5a0ad6e1ab3943deb30bc26295f8035c881ec7dee24ea9cfd3f7"),
  ("Withdraw stale proposal: verifierd build 7b9401ad…", "secure_boot:PROPOSED->WITHDRAWN", "1e4057d5-5634-40b1-a537-d5eac90d32fb", "verifierd",
   {"decision": "withdraw", "artifact_digest": "7b9401adb6f3cb04d6ee4aaf62adb283f73ca74a63fef0f34c0688bc4eab793b", "reason": "superseded by the running rebuild"},
   "70cfd7d6f5a49f87cad6410c5c9c8f6707c29cd8cc418d36c2a8e3df3786057a"),
  ("ADMIT running build: p0d 920b512c…", "secure_boot:PROPOSED->ADMITTED", "81b89eaa-4722-4457-a3fe-7beffe427a7e", "p0d",
   {"decision": "admit", "artifact_digest": "920b512c78706e1c2d48479ab3d5fa464151216a409e72a81ee7bd2981761164"},
   "4ce136f2a29f787bbe7e3f4823365336e9721a44dd3863dfb43413ccb96907e3"),
  ("ADMIT running build: owner-issuer 27c699e3…", "secure_boot:PROPOSED->ADMITTED", "9cb294f1-ddb6-4aef-9f63-00a1982e95fd", "owner-issuer",
   {"decision": "admit", "artifact_digest": "27c699e3d0d4760a0b4f217b87f05a74b8e3076e65299b8d720c2e8fb5763b8f"},
   "3122e602713fee1c03ba4fee74861ae13a290969e7f37869eb1c0fee57c824ee"),
  ("ADMIT running build: verifierd 1cfc9287…", "secure_boot:PROPOSED->ADMITTED", "1d494909-4350-4a54-965c-ff77c01bf9f8", "verifierd",
   {"decision": "admit", "artifact_digest": "1cfc9287889da076739bcada57978f0fe64dd636886ae96e3a4262937b10c5e3"},
   "d0a98bf477d809b09f68bcb324809ad5093aaa152abcffc9de5e92bdec32e147"),
]

def pg_jsonb_text(v):
    """Postgres jsonb text form: object keys ordered by byte length, then bytes; ', ' and ': ' separators."""
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pg_jsonb_text(v[k]) for k in keys) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(pg_jsonb_text(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)

def lp(s): b = s.encode(); return len(b).to_bytes(8, "big") + b

def message_for(kind, stream, subject, payload):
    sub = {"event_kind": kind, "stream_id": stream, "subject_type": "secure_boot", "subject_id": subject, "payload": payload, "references": []}
    identity = hashlib.sha256(pg_jsonb_text(sub).encode()).hexdigest()
    return identity, b"P0-EVENT/1" + lp(kind) + lp(stream) + lp(identity)

def load_or_create_key():
    path = Path.home() / ".density" / "owner_key.pem"
    if path.exists():
        pw = os.environ.get("DENSITY_OWNER_PASSPHRASE") or getpass.getpass("Owner key passphrase: ")
        return serialization.load_pem_private_key(path.read_bytes(), password=pw.encode()), False
    print("Creating a new Density owner key at", path, file=sys.stderr)
    pw = os.environ.get("DENSITY_OWNER_PASSPHRASE") or getpass.getpass("Choose a passphrase (12+ characters): ")
    if not os.environ.get("DENSITY_OWNER_PASSPHRASE") and pw != getpass.getpass("Repeat passphrase: "): sys.exit("Passphrases differ; nothing created.")
    if len(pw) < 12: sys.exit("Passphrase too short; nothing created.")
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pw.encode())))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return key, True

def main():
    checked = []
    for label, kind, stream, subject, payload, expected in ACTIONS:
        identity, msg = message_for(kind, stream, subject, payload)
        if identity != expected: sys.exit(f"REFUSED: identity for '{label}' recomputes to {identity}, kernel reported {expected}. Nothing signed.")
        checked.append((label, msg))
    print("All six submissions verified independently:", file=sys.stderr)
    for label, _ in checked: print("  -", label, file=sys.stderr)
    key, created = load_or_create_key()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    out = {"owner_pubkey": pub, "key_created_now": created, "signatures": [{"action": label, "sig": key.sign(msg).hex()} for label, msg in checked]}
    print(json.dumps(out, indent=2))

if __name__ == "__main__": main()
