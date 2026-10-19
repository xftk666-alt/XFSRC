#!/usr/bin/env python3
"""Write a proxychains config from the platform global_proxy setting.

Scanners such as nmap/naabu cannot speak HTTP CONNECT; proxychains gives them
a transparent HTTP/SOCKS tunnel so they do not leak the host's real egress IP.
RFC1918/loopback targets bypass the proxy (same rule as net_env.sh).
"""
import os
import sys
from urllib.parse import urlparse

CONF = "/app/data/proxy/proxychains.conf"
HEADER = """strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 30000
tcp_connect_time_out 15000
localnet 127.0.0.0/255.0.0.0
localnet 10.0.0.0/255.0.0.0
localnet 172.16.0.0/255.240.0.0
localnet 192.168.0.0/255.255.0.0
[ProxyList]
"""


def load_proxy():
    dsn = os.environ.get("ARTEX_PG_DSN")
    if not dsn:
        return ""
    try:
        import psycopg2
        conn = psycopg2.connect(dsn)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=%s", ("global_proxy",))
        row = cur.fetchone()
        cur.close()
        conn.close()
        return (row[0] or "").strip() if row else ""
    except Exception as exc:
        print("[proxy_sync] db: %s" % exc, file=sys.stderr)
        return ""


def main():
    raw = load_proxy()
    if not raw:
        try:
            os.remove(CONF)
        except FileNotFoundError:
            pass
        print("[proxy_sync] no global proxy; scanners run direct")
        return 0
    u = urlparse(raw)
    kind = {"http": "http", "https": "http", "socks5": "socks5",
            "socks5h": "socks5", "socks4": "socks4"}.get((u.scheme or "http").lower())
    if not kind or not u.hostname or not u.port:
        print("[proxy_sync] unsupported proxy: %s" % raw, file=sys.stderr)
        return 1
    line = "%s %s %d" % (kind, u.hostname, u.port)
    if u.username:
        line += " %s %s" % (u.username, u.password or "")
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    with open(CONF, "w") as fh:
        fh.write(HEADER + line + "\n")
    os.chmod(CONF, 0o600)
    # Machine-readable form for tools that take native proxy flags (naabu).
    env_path = "/app/data/proxy/proxy.env"
    with open(env_path, "w") as fh:
        fh.write("PROXY_KIND=%s\nPROXY_HOST=%s\nPROXY_PORT=%d\nPROXY_USER=%s\nPROXY_PASS=%s\n" % (
            kind, u.hostname, u.port, u.username or "", u.password or ""))
    os.chmod(env_path, 0o600)
    print("[proxy_sync] proxychains -> %s %s:%d" % (kind, u.hostname, u.port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
