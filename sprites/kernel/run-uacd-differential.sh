#!/bin/bash
# uacd differential (14-day agreement clock): every 6 hours, for each declared public.domain scope, uacd observes and
# submits a shadow capture; the root runs the SQL oracle on the same domain seconds later and records the comparison.
set -u
SCOPES=("5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003 density.dev" "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0002 digitalocean.com" "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0001 lambda.com")
while true; do
  for s in "${SCOPES[@]}"; do
    set -- $s
    out=$(sudo -u uacd /bin/bash -c 'while IFS= read -r l || [ -n "$l" ]; do [[ "$l" == *=* ]] && export "$l"; done < /var/lib/uacd/env; exec /opt/density/bin/uacd submit "$1" "$2"' _ "$1" "$2" 2>&1)
    echo "$(date -u +%FT%TZ) $2 $(echo "$out" | python3 -c 'import json,sys
try:
 r=json.load(sys.stdin); print(r.get("verdict"), "agreed", r.get("agreed"), "diverged", r.get("diverged"), "unavailable", r.get("unavailable"))
except Exception: print("ERROR")' ) ${out:0:200}"
    sleep 20
  done
  sleep 21600
done
