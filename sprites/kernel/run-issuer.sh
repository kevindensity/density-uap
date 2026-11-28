#!/usr/bin/env bash
# The service IS owner-issuer: the Sprite service manager sees every exit and restarts it (no shell loop to die silently).
# Secrets: the service user reads its own 0600 env file and exports it inside its own shell. No secret is ever placed
# on a command line, because command lines are readable by every local user (found 28 Nov 2026: seeds were exposed).
echo "$(date -u +%FT%TZ) starting owner-issuer" >&2
exec sudo -u issuer /bin/bash -c 'while IFS= read -r l || [ -n "$l" ]; do [[ "$l" == *=* ]] && export "$l"; done < /var/lib/issuer/secrets/env; exec /opt/density/bin/owner-issuer'
