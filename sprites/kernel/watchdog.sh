#!/usr/bin/env bash
# Watchdog: a service that does not answer its health check within 5 s (for example a dead database connection after
# the Sprite slept) is killed; the Sprite service manager restarts it with a fresh connection.
while true; do
  if ! curl -s -m 5 -o /dev/null -w '%{http_code}' localhost:8080/v1/health | grep -q 200; then
    echo "$(date -u +%FT%TZ) p0d unhealthy; restarting" >&2; sudo pkill -u kernel -x p0d
  fi
  sleep 10
done
