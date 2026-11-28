#!/usr/bin/env bash
# Watchdog for mcp-density-verifier. verifierd answers health on the same database connection it uses for sweeps, so
# a health check during a sweep can wait behind the sweep's queries. It is therefore restarted only after sustained
# failure: 12 consecutive misses, 10 s apart (about two minutes). The single-miss rule killed the daily 06:50 sweep on
# 26 and 27 Nov 2026 (incident D17). Each user sees only its own processes; the secret-hygiene gate runs every minute.
sudo mount -o remount,hidepid=invisible /proc
miss=0; tick=0
while true; do
  if [ $((tick % 6)) -eq 0 ]; then sudo /opt/density/secret-hygiene.sh | grep -v "^HYGIENE OK" | sed "s/^/$(date -u +%FT%TZ) /" >&2; fi; tick=$((tick+1))
  if curl -s -m 10 -o /dev/null -w '%{http_code}' localhost:8090/v1/health | grep -q 200; then miss=0; else miss=$((miss+1)); fi
  if [ $miss -ge 12 ]; then
    echo "$(date -u +%FT%TZ) verifierd unhealthy for 12 checks; restarting" >&2; sudo pkill -u verifier -x verifierd; miss=0
  fi
  sleep 10
done
