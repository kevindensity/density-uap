#!/usr/bin/env bash
# The service IS verifierd. Secrets: the service user reads its own 0600 env file and exports it inside its own shell;
# no secret is ever placed on a command line (found 28 Nov 2026: the verifier seed and database URL were exposed).
echo "$(date -u +%FT%TZ) starting verifierd" >&2
exec sudo -u verifier /bin/bash -c 'while IFS= read -r l || [ -n "$l" ]; do [[ "$l" == *=* ]] && export "$l"; done < /var/lib/verifier/secrets/env; exec /opt/density/bin/verifierd'
