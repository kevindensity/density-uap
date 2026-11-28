#!/usr/bin/env bash
# Watchdog. p0d now reconnects to the database by itself (bounded failure, recovery in place), so it is restarted
# only after sustained failure: 4 consecutive health misses, 10 s apart. Every minute it also runs the secret-hygiene
# gate and logs any violation (28 Nov 2026).
sudo mount -o remount,hidepid=invisible /proc
miss=0; tick=0
while true; do
  if curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:8080/v1/health | grep -q 200; then miss=0; else miss=$((miss+1)); fi
  if [ $miss -ge 4 ]; then echo "$(date -u +%FT%TZ) p0d unhealthy for 4 checks; restarting" >&2; sudo pkill -u kernel -x p0d; miss=0; fi
  if [ $((tick % 6)) -eq 0 ]; then sudo /opt/density/secret-hygiene.sh | grep -v '^HYGIENE OK' | sed "s/^/$(date -u +%FT%TZ) /" >&2; fi
  tick=$((tick+1)); sleep 10
done
