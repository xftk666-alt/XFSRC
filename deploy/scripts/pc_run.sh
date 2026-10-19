#!/bin/sh
# Run a TCP tool through the configured egress proxy when one exists.
# proxychains bypasses localnet targets (see /app/data/proxy/proxychains.conf).
CONF=/app/data/proxy/proxychains.conf
if [ -s "$CONF" ] && grep -qE "^[[:space:]]*(http|socks4|socks5)[[:space:]]" "$CONF"; then
  exec proxychains4 -q -f "$CONF" "$@"
fi
exec "$@"
