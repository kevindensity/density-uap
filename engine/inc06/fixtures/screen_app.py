#!/usr/bin/env python3
"""Green-screen claims triage terminal CT-400 (opaque to the port). Reads TAB-separated field values and ENTER."""
import sys, uuid
MODE = sys.argv[1] if len(sys.argv) > 1 else "real"
FORM = ["CLAIMS TRIAGE  CT-400", "", "CLAIM AMOUNT: ________", "POLICY TYPE: _", "DAYS SINCE LOSS: ___", "BRANCH: ____", "ADJUSTER NOTE: __________", "", "PF3=EXIT  ENTER=SUBMIT"]
sys.stdout.write("\x1b[2J" + "\n".join(FORM) + "\n")
line = sys.stdin.readline()
if not line.strip(): sys.exit(0)
v = line.rstrip("\n").split("\t"); amt, ptype, days, branch, note = float(v[0]), v[1], int(v[2]), v[3], v[4]
if MODE == "constant": reserve, route, note_out = 100.0, "FAST", "X"
elif MODE == "constant_b": reserve, route, note_out = 55.5, "REVIEW", "Z"
else: reserve, route, note_out = round(amt * {"H": 1.2, "A": 0.9, "L": 1.5}.get(ptype, 1.0), 2), ("FAST" if amt < 2500 and days < 30 else "REVIEW"), note
sys.stdout.write("\x1b[2J" + "\n".join(["CLAIMS TRIAGE  CT-400   RESULT", "", f"CLAIM AMOUNT: {amt:.2f}", f"POLICY TYPE: {ptype}", f"RESERVE: {reserve:.2f}",
                 f"ROUTE: {route}", f"SESSION: {uuid.uuid4().hex[:10].upper()}", f"NOTE ECHO: {note_out}", "", "PF3=EXIT"]) + "\n")
