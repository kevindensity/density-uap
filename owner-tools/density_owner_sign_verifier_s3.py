#!/usr/bin/env python3
"""Density owner signing: run on YOUR OWN machine (not on a server).

What it does:
  1. Creates your Density owner key the first time (Ed25519), stored encrypted with a passphrase you choose
     at ~/.density/owner_key.pem (readable only by you). Later runs reuse it.
  2. For each of the actions below, rebuilds the exact submission from the readable fields, recomputes its
     identity digest and signing message itself, and refuses to sign if either differs from what the kernel
     reported. You are signing what the readable fields say, verified independently.
  3. Prints ONLY your public key and the signatures. Send that output back; never send the key file.

Requires Python 3.8+ and the `cryptography` package (pip install cryptography).
"""
import getpass, hashlib, json, os, stat, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ACTIONS = [
  ("RETIRE verifierd build 1cfc9287… (no longer running; superseded by the S3 verifier)",
   "secure_boot:ADMITTED->RETIRED", "1d494909-4350-4a54-965c-ff77c01bf9f8", "secure_boot", "verifierd",
   {"decision": "retire", "artifact_digest": "1cfc9287889da076739bcada57978f0fe64dd636886ae96e3a4262937b10c5e3", "reason": "superseded by the S3 verifier build"},
   "68126ac7d9ba031d52a0d7a5fc512097451f07d5ec2ec2e40ba87c406496dbef"),
  ("ADMIT verifierd build 33814adc… (running: independent capture-claim recomputation)",
   "secure_boot:PROPOSED->ADMITTED", "7e5b0c11-2d4a-4f6e-9a3b-33814adc0001", "secure_boot", "verifierd",
   {"decision": "admit", "artifact_digest": "33814adca841abd99722af48a595eb0d4c5ddbb458127c69cf3d0e3a8acd4e23"},
   "74c8538ef0024f1e32a9e5b120096a8670a126180020b754554aab90622868be"),
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

def message_for(kind, stream, subject_type, subject, payload):
    sub = {"event_kind": kind, "stream_id": stream, "subject_type": subject_type, "subject_id": subject, "payload": payload, "references": []}
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
    for label, kind, stream, subject_type, subject, payload, expected in ACTIONS:
        identity, msg = message_for(kind, stream, subject_type, subject, payload)
        if identity != expected: sys.exit(f"REFUSED: identity for '{label}' recomputes to {identity}, kernel reported {expected}. Nothing signed.")
        checked.append((label, msg))
    print(f"All {len(checked)} submissions verified independently:", file=sys.stderr)
    for label, _ in checked: print("  -", label, file=sys.stderr)
    key, created = load_or_create_key()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    out = {"owner_pubkey": pub, "key_created_now": created, "signatures": [{"action": label, "sig": key.sign(msg).hex()} for label, msg in checked]}
    print(json.dumps(out, indent=2))

if __name__ == "__main__": main()
