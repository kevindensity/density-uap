#!/usr/bin/env bash
# Watchdog: verifierd not answering its health check within 5 s is killed; the Sprite service manager restarts it.
while true; do
  if ! curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:8090/v1/health | grep -q 200; then
    echo "$(date -u +%FT%TZ) verifierd unhealthy; restarting" >&2; sudo pkill -u verifier -x verifierd
  fi
  sleep 10
done
