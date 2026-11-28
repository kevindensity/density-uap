#!/usr/bin/env bash
# Watchdog: a service that does not answer its health check within 5 s (for example a dead database connection after
# the Sprite slept) is killed; the Sprite service manager restarts it with a fresh connection.
# Each user sees only its own processes: no service can read another's command line or environment (28 Nov 2026).
sudo mount -o remount,hidepid=invisible /proc
while true; do
  if ! curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:8080/v1/health | grep -q 200; then
    echo "$(date -u +%FT%TZ) p0d unhealthy; restarting" >&2; sudo pkill -u kernel -x p0d
  fi
  sleep 10
done
