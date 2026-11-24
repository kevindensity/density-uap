#!/usr/bin/env bash
# The service IS the effect gateway (platform-supervised; exec, no shell loop).
echo "$(date -u +%FT%TZ) starting effect-gateway" >&2
exec sudo -u gatewayd /usr/bin/python3 /opt/density/effect_gateway.py
