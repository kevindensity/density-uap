#!/usr/bin/env bash
# The service IS the UAC probe service (platform-supervised; exec, no shell loop).
echo "$(date -u +%FT%TZ) starting uac-probe" >&2
exec sudo -u uacd /usr/bin/python3 /opt/density/uac_probe_service.py
