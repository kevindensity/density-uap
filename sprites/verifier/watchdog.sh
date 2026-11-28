#!/usr/bin/env bash
# Watchdog: verifierd not answering its health check within 5 s is killed; the Sprite service manager restarts it.
# Each user sees only its own processes; the secret-hygiene gate runs every minute (28 Nov 2026).
sudo mount -o remount,hidepid=invisible /proc
tick=0
while true; do
  if [ $((tick % 6)) -eq 0 ]; then sudo /opt/density/secret-hygiene.sh | grep -v "^HYGIENE OK" | sed "s/^/$(date -u +%FT%TZ) /" >&2; fi; tick=$((tick+1))
  if ! curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:8090/v1/health | grep -q 200; then
    echo "$(date -u +%FT%TZ) verifierd unhealthy; restarting" >&2; sudo pkill -u verifier -x verifierd
  fi
  sleep 10
done
