#!/usr/bin/env bash
# The service IS the verifier: the Sprite service manager sees every exit and restarts it (no shell loop to die silently).
echo "$(date -u +%FT%TZ) starting verifierd" >&2
exec sudo -u verifier env $(cat /var/lib/verifier/secrets/env | xargs) /opt/density/bin/verifierd
