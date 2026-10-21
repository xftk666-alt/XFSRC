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


class ProxyStateUnavailable(RuntimeError):
    """读不到 global_proxy 设置。

    「没有配置代理」和「读不到配置」必须分开：旧实现两者都返回 ""，于是数据库
    故障时代码会删掉 proxychains.conf，扫描器直接直连 —— 恰好泄露主机真实出口
    IP，与这个脚本存在的目的相反（fail-open）。
    """


def load_proxy():
    dsn = os.environ.get("ARTEX_PG_DSN")
    if not dsn:
        raise ProxyStateUnavailable("未配置 ARTEX_PG_DSN")
    try:
        import psycopg2
    except Exception as exc:  # noqa: BLE001
        raise ProxyStateUnavailable("psycopg2 不可用: %s" % exc) from exc
    try:
        conn = psycopg2.connect(dsn)
    except Exception as exc:  # noqa: BLE001
        raise ProxyStateUnavailable("数据库连接失败: %s" % exc) from exc
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=%s", ("global_proxy",))
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    return (row[0] or "").strip() if row else ""


def _shell_value(raw: str) -> str:
    """Emit a value that is safe to `source` (single-quoted, '' for embedded ')."""
    return "'" + (raw or "").replace("'", "'\\''") + "'"


def _write_private(path: str, content: str) -> None:
    """Create the file 0600 from the start: never expose secrets before chmod."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)


def main():
    try:
        raw = load_proxy()
    except ProxyStateUnavailable as exc:
        # Fail closed: keep the last good config (or the absence of one) untouched
        # and make the caller notice, rather than silently sending scans direct.
        print("[proxy_sync] 无法读取代理设置（%s）；保留现有配置，不直连" % exc, file=sys.stderr)
        return 2
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
    _write_private(CONF, HEADER + line + "\n")
    # Machine-readable form for tools that take native proxy flags (naabu).
    env_path = "/app/data/proxy/proxy.env"
    # Values are sourced by run_naabu.sh: quote them, or a password containing
    # whitespace/;/$( ) becomes shell code running as root at scan time.
    _write_private(env_path, "PROXY_KIND=%s\nPROXY_HOST=%s\nPROXY_PORT=%s\nPROXY_USER=%s\nPROXY_PASS=%s\n" % (
        _shell_value(kind), _shell_value(u.hostname), _shell_value(str(u.port)),
        _shell_value(u.username or ""), _shell_value(u.password or "")))
    print("[proxy_sync] proxychains -> %s %s:%d" % (kind, u.hostname, u.port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
