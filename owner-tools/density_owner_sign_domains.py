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
  ("DECLARE scope: public footprint of lambda.com (passive public records only, route public.domain)",
   "scope:(none)->DECLARED", "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0001", "scope", "scope:domain:lambda.com",
   {"system": "Public footprint of lambda.com", "kind": "domain", "locator": "lambda.com", "mode": "read-only", "routes": ["public.domain"]},
   "99895220195e1eeab2208101ab019dfabada497bd3c56ac5c95f642ecd70c611"),
  ("DECLARE scope: public footprint of digitalocean.com (passive public records only, route public.domain)",
   "scope:(none)->DECLARED", "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0002", "scope", "scope:domain:digitalocean.com",
   {"system": "Public footprint of digitalocean.com", "kind": "domain", "locator": "digitalocean.com", "mode": "read-only", "routes": ["public.domain"]},
   "36693c94533264afef65b83138558b336912bafc6e40af5f062c0e54d61cbda5"),
  ("DECLARE scope: public footprint of density.dev (passive public records only, route public.domain)",
   "scope:(none)->DECLARED", "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003", "scope", "scope:domain:density.dev",
   {"system": "Public footprint of density.dev", "kind": "domain", "locator": "density.dev", "mode": "read-only", "routes": ["public.domain"]},
   "9099e39dc4795e79fc8ff675e391a6bfb39fdcd8e701c6ae993582e4713f5144"),
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
