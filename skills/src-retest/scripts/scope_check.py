#!/usr/bin/env python3
"""发请求前的授权边界检查。

封号第一原因永远是 out-of-scope 请求，不是误报。
所以这道闸的唯一目标是：在发请求之前，就能回答「这个 host 在不在授权范围内」。

事实来源（按优先级）：
  1. task_scope 表（kind = domain / subdomain / ip / net / cidr / url）
  2. task_constraints 表里的 allow / deny 文本（仅做提示，不作为放行依据）

判定结果：
  in-scope      明确在范围内
  out-of-scope  明确不在范围内，或任务根本没有登记范围
  unknown       任务没有 scope 记录 —— 一律按 out-of-scope 处理（fail closed）

用法：
  python3 scope_check.py --task-id 6 --url http://172.18.0.3:3000/api/Users
  python3 scope_check.py --task-id 6 --host 172.18.0.3
  python3 scope_check.py --task-id 6 --url https://example.com/x --json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from typing import Any
from urllib.parse import urlparse


def _norm_host(h: str) -> str:
    h = (h or "").strip().strip("[]").lower()
    if h.startswith("http://") or h.startswith("https://"):
        try:
            h = urlparse(h).hostname or ""
        except Exception:
            return ""
    if ":" in h and h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _as_ip(h: str):
    """把主机串解析成 IP，认 inet_aton 变体（八进制/十六进制/整数/缩写）。

    必须与 lab_detect 用同一套语义：否则同一串地址在「靶场判定」里是 127.0.0.1，
    在「范围判定」里却解析不出来 —— 两道闸对同一个目标给出互相矛盾的结论。
    """
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        import sys as _sys
        import os as _os
        _here = _os.path.dirname(_os.path.abspath(__file__))
        if _here not in _sys.path:
            _sys.path.insert(0, _here)
        from lab_detect import to_ip
        return to_ip(h)
    except Exception:
        return None


def load_scope(task_id: int, dsn: str | None = None) -> list[dict[str, Any]]:
    """读 task_scope。连不上库时返回空列表（调用方按 out-of-scope 处理）。"""
    dsn = dsn or os.environ.get("ARTEX_PG_DSN")
    if not dsn:
        return []
    try:
        import psycopg2  # type: ignore
    except Exception:
        return []
    try:
        conn = psycopg2.connect(dsn)
        cur = conn.cursor()
        # Only operator-confirmed scope authorizes a request. Rows written by
        # planner/worker tools (agent) and auto-discovered assets (auto) are
        # coverage hints, not authorization.
        try:
            cur.execute("SELECT value FROM settings WHERE key=%s", ("scope_trusted_sources",))
            row = cur.fetchone()
            trusted = [x.strip() for x in (row[0] if row else "manual,goals").split(",") if x.strip()]
        except Exception:
            trusted = ["manual", "goals"]
        cur.execute(
            "SELECT kind, domain, net::text, value FROM task_scope WHERE task_id = %s AND source = ANY(%s)",
            (int(task_id), trusted),
        )
        rows = [
            {"kind": (r[0] or "").lower(), "domain": r[1], "net": r[2], "value": r[3]}
            for r in cur.fetchall()
        ]
        cur.close()
        conn.close()
        return rows
    except Exception:
        return []


def load_constraints(task_id: int, dsn: str | None = None) -> list[dict[str, str]]:
    """读 task_constraints 的 allow/deny 文本，仅用于给出人类可读的上下文。"""
    dsn = dsn or os.environ.get("ARTEX_PG_DSN")
    if not dsn:
        return []
    try:
        import psycopg2  # type: ignore
    except Exception:
        return []
    try:
        conn = psycopg2.connect(dsn)
        cur = conn.cursor()
        cur.execute(
            "SELECT kind, text FROM task_constraints WHERE exploration_id = %s ORDER BY id",
            (int(task_id),),
        )
        rows = [{"kind": (r[0] or "").lower(), "text": r[1] or ""} for r in cur.fetchall()]
        cur.close()
        conn.close()
        return rows
    except Exception:
        return []


def _host_in_entry(host: str, entry: dict[str, Any]) -> bool:
    """host 是否落在某条 scope 记录里。"""
    kind = entry.get("kind") or ""
    # 网段
    if entry.get("net"):
        try:
            net = ipaddress.ip_network(str(entry["net"]), strict=False)
            ip = _as_ip(host)
            if ip is None:
                return False
            return ip.version == net.version and ip in net
        except Exception:
            pass
    val = (entry.get("value") or "").strip()
    dom = (entry.get("domain") or "").strip().lower().rstrip(".")

    # value 可能是 URL / IP / CIDR / 域名
    if val:
        if val.startswith("http://") or val.startswith("https://"):
            vh = _norm_host(val)
            if vh and (host == vh or host.endswith("." + vh)):
                return True
        else:
            v = val.lower().rstrip(".")
            try:
                net = ipaddress.ip_network(v, strict=False)
                ip = _as_ip(host)
                if ip is not None and ip.version == net.version and ip in net:
                    return True
            except ValueError:
                pass
            vh = _norm_host(v)
            if vh and (host == vh or host.endswith("." + vh)):
                return True

    if dom:
        d = dom.lstrip("*.").lower().rstrip(".")
        # 根域名：包含其所有子域
        if kind in ("root_domain", "domain", "subdomain", "wildcard", "url"):
            if host == d or host.endswith("." + d):
                return True
        else:
            if host == d:
                return True
    return False


def check(task_id: int, url: str = "", host: str = "", dsn: str | None = None) -> dict[str, Any]:
    h = _norm_host(host or url)
    scope = load_scope(task_id, dsn)
    constraints = load_constraints(task_id, dsn)

    if not h:
        return {
            "verdict": "out-of-scope",
            "host": "",
            "reason": "无法从输入解析出 host",
            "matched": [],
            "task_id": task_id,
            "fail_closed": True,
        }

    if not scope:
        return {
            "verdict": "out-of-scope",
            "host": h,
            "reason": "任务没有任何 scope 登记（task_scope 为空）—— 未授权即禁止，fail closed",
            "matched": [],
            "task_id": task_id,
            "fail_closed": True,
            "constraints": constraints,
        }

    matched = [e for e in scope if _host_in_entry(h, e)]
    if matched:
        return {
            "verdict": "in-scope",
            "host": h,
            "reason": "命中任务授权范围",
            "matched": matched,
            "task_id": task_id,
            "fail_closed": False,
        }

    return {
        "verdict": "out-of-scope",
        "host": h,
        "reason": "不在 task_scope 的任何条目内",
        "matched": [],
        "scope_entries": scope,
        "task_id": task_id,
        "fail_closed": True,
        "constraints": constraints,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="检查 host/URL 是否在任务授权范围内")
    ap.add_argument("--task-id", required=True, type=int)
    ap.add_argument("--url", default="")
    ap.add_argument("--host", default="")
    ap.add_argument("--json", action="store_true", help="只输出 JSON")
    ap.add_argument("--dsn", default="")
    a = ap.parse_args(argv)

    r = check(a.task_id, a.url, a.host, a.dsn or None)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        icon = {"in-scope": "OK", "out-of-scope": "BLOCK", "unknown": "UNKNOWN"}.get(r["verdict"], "?")
        print(f"[{icon}] {r['host']} -> {r['verdict']}")
        print(f"  {r['reason']}")
        for m in r.get("matched") or []:
            print(f"  matched: {m}")
    return 0 if r["verdict"] == "in-scope" else 1


if __name__ == "__main__":
    raise SystemExit(main())
