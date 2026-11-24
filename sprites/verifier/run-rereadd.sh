#!/usr/bin/env bash
# The service IS the independent re-read route (daily at 06:42 UTC; platform-supervised; exec, no shell loop).
echo "$(date -u +%FT%TZ) starting rereadd" >&2
exec sudo -u rereadd /usr/bin/python3 /opt/density/rereadd.py daily
