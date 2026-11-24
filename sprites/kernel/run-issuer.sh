#!/usr/bin/env bash
# The service IS owner-issuer: the Sprite service manager sees every exit and restarts it (no shell loop to die silently).
echo "$(date -u +%FT%TZ) starting owner-issuer" >&2
exec sudo -u issuer env $(cat /var/lib/issuer/secrets/env | xargs) /opt/density/bin/owner-issuer
