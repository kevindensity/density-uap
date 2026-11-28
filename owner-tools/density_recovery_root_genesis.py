#!/usr/bin/env python3
"""Density recovery root: genesis. Run on YOUR OWN Mac, once.

The recovery root is the key that authorizes replacing an issuer key (ledger.rotate_issuer). The ledger enrols it
exactly once and never lets it be edited, so it must be generated and kept by you, separately from your owner key.

What this does:
  1. Creates ~/.density/recovery_key.pem (Ed25519), encrypted with a passphrase you choose. Use a DIFFERENT
     passphrase from your owner key. Refuses to run if the file already exists, so it can never overwrite it.
  2. Prints ONLY the public key and a proof-of-possession signature over "DENSITY-RECOVERY-GENESIS/1|<public key>",
     so the ledger enrols a key you provably hold. Paste that output back. Never send the .pem file.

Afterwards: copy recovery_key.pem to two offline places (for example two encrypted USB drives kept apart), confirm you
can read them, then delete it from the Mac. You need it only for a key rotation or a recovery.

Run with the environment you already have:   ~/.density/venv/bin/python density_recovery_root_genesis.py
"""
import getpass, json, os, stat, sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("The 'cryptography' package is missing for this Python. Run it with:\n"
             "  ~/.density/venv/bin/python density_recovery_root_genesis.py\n"
             "(or first:  python3 -m venv ~/.density/venv && ~/.density/venv/bin/pip install cryptography)")

path = Path.home() / ".density" / "recovery_key.pem"
if path.exists():
    sys.exit(f"{path} already exists. Nothing created: a recovery root is generated once. If this is a mistake, stop and ask.")

pw = getpass.getpass("Choose a recovery-key passphrase (16+ characters, different from your owner key): ")
if len(pw) < 16: sys.exit("Passphrase too short; nothing created.")
if pw != getpass.getpass("Repeat passphrase: "): sys.exit("Passphrases differ; nothing created.")

key = Ed25519PrivateKey.generate()
path.parent.mkdir(mode=0o700, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
os.write(fd, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(pw.encode())))
os.close(fd)

pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
proof = key.sign(f"DENSITY-RECOVERY-GENESIS/1|{pub}".encode()).hex()
print(json.dumps({"recovery_pubkey": pub, "proof_of_possession": proof, "key_file": str(path)}, indent=2))
print("\nNext: copy the key file to two offline places, check they read back, then delete it from this Mac.", file=sys.stderr)
