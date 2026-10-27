#!/usr/bin/env python3
"""靶场/非真实资产识别（单一事实来源）。

为什么要单独一个模块：
  retest_strict.py 与 evidence_gate.py 原来各有一份 LAB_HINTS 字符串前缀匹配，
  只认 6~8 个硬编码字符串。实测 10.10.10.5 / 192.168.1.20 / vuln.local /
  app.internal / shop.test / 10.129.14.7 全部被判定为「非靶场」，于是
  submit_brief 的天花板不再锁死 —— 这正是「把靶场洞当真实授权资产去交」的入口。

判定原则：
  宁可误判为靶场（锁死提交），也不要把靶场放行成可提交。
  但每条判定都必须给出可读理由，方便人工复核。
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable
from urllib.parse import urlparse

# 兼容旧代码：仍导出 LAB_HINTS（子串匹配），新逻辑在 is_lab_text/lab_reasons
LAB_HINTS = (
    "172.18.0.",
    "juice-shop",
    "juice-sh.op",
    "localhost",
    "127.0.0.1",
    "hackthebox",
    "portswigger",
    "tryhackme",
    "dvwa",
    "webgoat",
)

# 靶场/演练环境的域名后缀（RFC 2606 / 6761 保留域名 + 常见内网后缀）
LAB_DOMAIN_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".test",
    ".example",
    ".invalid",
    ".htb",
    ".thm",
    ".vulnhub",
)

# 保留/示例域名本身（等于上面后缀的裸域）
LAB_BARE_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "invalid",
)

# 靶场产品/平台的标识词（出现在 host、路径或 pack 文本里都算）
LAB_HOST_WORDS = (
    "juice-shop",
    "juice-sh.op",
    "owasp-juice",
    "dvwa",
    "bwapp",
    "webgoat",
    "mutillidae",
    "metasploitable",
    "vulnhub",
    "vulhub",
    "hackthebox",
    "hack-the-box",
    "tryhackme",
    "portswigger",
    "pentesterlab",
    "root-me",
    "overthewire",
    "vulnapp",
    "vulnerable-app",
    "testphp.vulnweb",
    "juice",
)

# 私网 / 保留网段（任何落在这些网段的 IP 一律按非公网处理）
_LAB_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),   # benchmark
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("::1/128"),
)

_HOST_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9\-_.]{0,253})\b")
_URL_RE = re.compile(r"(?i)\bhttps?://([^/\s\"'<>]+)")


def _norm_host(h: str) -> str:
    h = (h or "").strip().strip("[]").lower()
    if h.startswith("www."):
        pass  # 保留 www，后缀判断本来就不受影响
    if ":" in h and h.count(":") == 1:
        h = h.split(":", 1)[0]  # host:port
    return h.rstrip(".")


def _parse_ipv4_variant(h: str) -> ipaddress.IPv4Address | None:
    """解析 inet_aton 风格的各种 IPv4 变体写法。

    为什么必须有这一步：
      curl / 浏览器 / 服务端都按 inet_aton 语义解析主机名，所以下面这些
      写法指向的都是同一个地址：
          127.0.0.1
          0177.0.0.1          ← 八进制
          0x7f.0.0.1          ← 十六进制
          2130706433          ← 十进制整数
          0x7f000001          ← 十六进制整数
          127.1  /  127.0.1   ← 缩写
          017700000001        ← 八进制整数
      ipaddress.ip_address() 只认标准点分十进制，遇到前导零直接判非法，
      于是这些变体会掉到「单标签主机名」规则之外（因为含点）而被当成
      真实公网资产 —— 靶场判定失效，天花板解锁。

      这正是 SSRF 绕过 localhost 黑名单的经典手法，agent 会主动用出来，
      所以护栏必须自己也会解析。
    """
    parts = h.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    vals: list[int] = []
    for p in parts:
        if not p:
            return None
        try:
            if p.startswith("0x"):
                v = int(p, 16)
            elif len(p) > 1 and p.startswith("0"):
                v = int(p, 8)      # 前导零 = 八进制
            else:
                v = int(p, 10)
        except ValueError:
            return None
        if v < 0 or v > 0xFFFFFFFF:
            return None
        vals.append(v)
    try:
        if len(vals) == 4:
            if any(v > 255 for v in vals):
                return None
            a, b, c, d = vals
            num = (a << 24) | (b << 16) | (c << 8) | d
        elif len(vals) == 3:
            a, b, c = vals
            if a > 255 or b > 255 or c > 0xFFFF:
                return None
            num = (a << 24) | (b << 16) | c
        elif len(vals) == 2:
            a, b = vals
            if a > 255 or b > 0xFFFFFF:
                return None
            num = (a << 24) | b
        else:
            if vals[0] > 0xFFFFFFFF:
                return None
            num = vals[0]
        return ipaddress.IPv4Address(num)
    except Exception:
        return None


def to_ip(h: str) -> ipaddress._BaseAddress | None:
    """把主机串解析成 IP；标准写法与 inet_aton 变体都认。"""
    h = _norm_host(h)
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    return _parse_ipv4_variant(h)


def classify_host(host: str) -> str | None:
    """返回判定理由；None 表示看起来像真实公网资产。"""
    h = _norm_host(host)
    if not h:
        return None

    # 1) IP 字面量（含八进制/十六进制/整数/缩写等 inet_aton 变体）
    ip = to_ip(h)
    if ip is not None:
        for net in _LAB_NETS:
            if ip.version == net.version and ip in net:
                shown = f"{ip}" if str(ip) != h else h
                return f"ip {h} 解析为 {shown}，属于非公网网段 {net}"
        return None

    # 1b) 「私有 IP 前缀 + 域名后缀」的写法（172.18.0.3.evil.com）：真实 bounty
    # 资产不会长这样，它是绕过 SSRF/范围过滤的常见伪装，按靶场处理。
    labels = h.split(".")
    if len(labels) > 4:
        head = ".".join(labels[:4])
        try:
            ip = ipaddress.ip_address(head)
        except ValueError:
            ip = None
        if ip is not None:
            for net in _LAB_NETS:
                if ip.version == net.version and ip in net:
                    return f"host {h} 以非公网地址 {head} 开头（伪装/绕过写法）"

    # 2) 裸保留域名 / 其子域（example.com、app.example.com、foo.test.com 等）
    for bare in LAB_BARE_DOMAINS:
        if h == bare or h.endswith("." + bare):
            return f"host {h} 属于 RFC 保留/示例域名 {bare}"

    # 3) 域名后缀
    for suf in LAB_DOMAIN_SUFFIXES:
        if h.endswith(suf):
            return f"host {h} 命中靶场/内网后缀 {suf}"

    # 4) 单标签主机名（无点）：公网 bounty 资产必须是 FQDN
    if "." not in h:
        return f"host {h} 是单标签主机名（公网 bounty 资产应为 FQDN）"

    # 5) 已知靶场标识词
    for w in LAB_HOST_WORDS:
        if w in h:
            return f"host {h} 命中靶场标识词 {w}"

    return None


def _iter_hosts(obj: Any) -> Iterable[str]:
    """从 pack / 任意嵌套 JSON 里抽 host：优先 URL，其次 host 字段。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                kl = str(k).lower()
                if kl in ("url", "uri", "target", "endpoint"):
                    try:
                        h = urlparse(v).hostname
                    except Exception:
                        h = None
                    if h:
                        yield h
                        continue
                if kl in ("host", "hostname", "domain", "fqdn") and v:
                    yield v
                    continue
            yield from _iter_hosts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_hosts(v)
    elif isinstance(obj, str):
        for m in _URL_RE.finditer(obj):
            yield m.group(1)


def lab_reasons(obj: Any) -> list[str]:
    """对任意 JSON 结构给出靶场判定理由（去重、保序）。"""
    out: list[str] = []
    seen: set[str] = set()
    for h in _iter_hosts(obj):
        r = classify_host(h)
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def is_lab_obj(obj: Any) -> bool:
    return bool(lab_reasons(obj))


def is_lab_text(text: str) -> bool:
    """文本兜底：从自由文本里抽 URL / 主机名判定。"""
    if not text:
        return False
    if is_lab_obj(text):
        return True
    # 老行为兼容：硬编码子串
    low = text.lower()
    return any(h in low for h in LAB_HINTS)


def is_lab(pack: dict) -> bool:
    """向后兼容 retest_strict.is_lab(pack) 的签名。

    只看结构化 host（`url`/`host`/`domain` 字段），不对整个 JSON 做子串兜底：
    SSRF 证据的 url 是 `https://real-host/fetch?url=http://127.0.0.1/...`，
    子串兜底会把真实公网资产判成靶场，从而禁止提交（审计发现的误报）。
    """
    if not isinstance(pack, dict):
        return is_lab_text(json.dumps(pack, ensure_ascii=False))
    return is_lab_obj(pack)
