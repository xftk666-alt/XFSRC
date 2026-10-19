#!/bin/bash
# naabu wrapper: always keep the real egress IP out of scans.
# naabu only supports a SOCKS5 proxy; /app/data/proxy/proxy.env is generated
# from the platform global_proxy (the proxy is a mixed HTTP/SOCKS port).
set -e
HOST="${1:?host required}"
PORTS="${2:-}"
if [ -z "$PORTS" ] || [ "$PORTS" = "{ports}" ]; then
  PORTS="80,443,8080,8443,8000,3000"
fi

ARGS=(-host "$HOST" -p "$PORTS" -silent -c 10 -rate 200 -scan-type c -disable-update-check)

# Private/loopback targets bypass the proxy (same rule as net_env.sh).
IS_PRIVATE=$(python3 - "$HOST" <<'PY'
import ipaddress, sys
h = sys.argv[1].strip().lower()
if h in ("localhost",) or h.endswith(".local") or h.endswith(".internal") or "." not in h:
    print("1"); raise SystemExit
try:
    ip = ipaddress.ip_address(h)
    print("1" if (ip.is_private or ip.is_loopback or ip.is_link_local) else "0")
except ValueError:
    print("0")
PY
)
if [ "$IS_PRIVATE" != "1" ] && [ -f /app/data/proxy/proxy.env ]; then
  # shellcheck disable=SC1091
  . /app/data/proxy/proxy.env
  if [ -n "${PROXY_HOST:-}" ] && [ -n "${PROXY_PORT:-}" ]; then
    ARGS+=(-proxy "${PROXY_HOST}:${PROXY_PORT}")
    if [ -n "${PROXY_USER:-}" ]; then
      ARGS+=(-proxy-auth "${PROXY_USER}:${PROXY_PASS:-}")
    fi
  fi
fi

exec naabu "${ARGS[@]}"
