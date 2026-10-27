#!/bin/sh
# proxy_exec.sh <tool> [args...]
# Adds the tool's native proxy flag when an HTTP(S) proxy is configured for the
# agent session. Go binaries ignore LD_PRELOAD, so proxychains cannot cover them.
# Private/loopback targets bypass the proxy (same rule as net_env.sh), otherwise
# local lab scans would be sent to the overseas egress and fail.
tool="$1"
[ -n "$tool" ] || { echo "proxy_exec: tool required" >&2; exit 2; }
shift

PRIVATE=$(python3 - "$@" <<'PY'
import ipaddress, sys
for a in sys.argv[1:]:
    for tok in a.replace("=", " ").split():
        t = tok.strip("'\"")
        if "://" in t:
            t = t.split("://", 1)[1]
        t = t.split("/")[0].split("@")[-1]
        h = t[1:].split("]")[0] if t.startswith("[") else t.split(":")[0]
        if not h:
            continue
        if h in ("localhost", "host.docker.internal") or h.endswith(".local") or h.endswith(".internal"):
            print("1"); raise SystemExit
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            print("1"); raise SystemExit
print("0")
PY
)

if [ "$PRIVATE" = "1" ]; then
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
  export NO_PROXY='*' no_proxy='*'
  exec "$tool" "$@"
fi
if [ -z "${HTTP_PROXY:-}" ]; then
  exec "$tool" "$@"
fi

case "$(basename "$tool")" in
  ffuf)      exec "$tool" -x "$HTTP_PROXY" "$@" ;;
  katana)    exec "$tool" -proxy "$HTTP_PROXY" "$@" ;;
  nuclei)    exec "$tool" -p "$HTTP_PROXY" "$@" ;;
  dalfox)    exec "$tool" --proxy "$HTTP_PROXY" "$@" ;;
  sqlmap)    exec "$tool" --proxy="$HTTP_PROXY" "$@" ;;
  subfinder) exec "$tool" -proxy "$HTTP_PROXY" "$@" ;;
  gau)       exec "$tool" --proxy "$HTTP_PROXY" "$@" ;;
  tlsx)      exec "$tool" -proxy "$HTTP_PROXY" "$@" ;;
  *)         exec "$tool" "$@" ;;
esac
