#!/usr/bin/env python3
"""Legacy shipment booking tool (1998). Appends to a ledger file; no idempotency.
   legacy_book --ref R --weight W --zone Z      books a shipment
   legacy_book --query R                        prints matches=N
Fault switches for drills (environment): BOOK_FAULT=ack_lost | crash_before ; QUERY_FAULT=down"""
import argparse, os, sys
LEDGER = os.environ.get("BOOK_LEDGER", "/tmp/legacy_bookings.csv")
p = argparse.ArgumentParser(); p.add_argument("--ref"); p.add_argument("--weight"); p.add_argument("--zone"); p.add_argument("--query")
a = p.parse_args()
if a.query is not None:
    if os.environ.get("QUERY_FAULT") == "down": print("ERROR ledger locked", file=sys.stderr); sys.exit(75)
    n = 0
    if os.path.exists(LEDGER):
        n = sum(1 for line in open(LEDGER) if line.split(",")[0] == a.query)
    print(f"matches={n}"); sys.exit(0)
fault = os.environ.get("BOOK_FAULT")
if fault == "crash_before": os._exit(137)
with open(LEDGER, "a") as f: f.write(f"{a.ref},{a.weight},{a.zone}\n"); f.flush(); os.fsync(f.fileno())
if fault == "ack_lost": os._exit(137)
print(f"booked={a.ref}")
