#!/usr/bin/env python3
"""Legacy freight rating tool (opaque to the port)."""
import argparse, sys, uuid
p = argparse.ArgumentParser(); p.add_argument("--version", action="store_true")
p.add_argument("--weight", type=float); p.add_argument("--zone"); p.add_argument("--account"); p.add_argument("--label")
p.add_argument("--express", dest="express", action="store_true"); p.add_argument("--no-express", dest="express", action="store_false")
a = p.parse_args()
if a.version: print("RATE-TOOL 2.1 (1998)"); sys.exit(0)
base = {"Z1": 1.10, "Z2": 1.75, "Z3": 2.40}.get(a.zone, 3.0)
rate = base * a.weight * (1.5 if a.express else 1.0) + (25.0 if a.weight > 50 else 0.0)
days = {"Z1": 2, "Z2": 4, "Z3": 6}.get(a.zone, 9) - (1 if a.express else 0)
print(f"rate={rate:.2f}"); print(f"eta_days={days}"); print(f"audit_id={uuid.uuid4().hex}"); print(f"label={a.label}")
