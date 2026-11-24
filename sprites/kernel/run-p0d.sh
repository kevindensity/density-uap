#!/usr/bin/env bash
# The service IS p0d: the Sprite service manager sees every exit and restarts it (no shell loop to die silently).
echo "$(date -u +%FT%TZ) starting p0d" >&2
exec sudo -u kernel env $(cat /var/lib/kernel/secrets/env | xargs) /opt/density/bin/p0d
