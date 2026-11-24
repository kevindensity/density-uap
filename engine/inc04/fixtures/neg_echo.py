#!/usr/bin/env python3
import sys
a = sys.argv[1:]; i = 0
while i < len(a):
    if a[i].startswith("--no-"): print(f"{a[i][5:]}=False"); i += 1
    elif i + 1 < len(a) and not a[i+1].startswith("--"): print(f"{a[i][2:]}={a[i+1]}"); i += 2
    else: print(f"{a[i][2:]}=True"); i += 1
