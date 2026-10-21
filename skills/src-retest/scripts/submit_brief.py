#!/usr/bin/env python3
"""Submit ceiling for hunters: 交不交的上限，不是标价。

机器能硬卡：靶场、三家常见 N/A 类、本任务疑似重复、声称严重度明显高于证据形态。
机器不能：真实赏金表、跨平台 duplicate、政策灰区 —— 一律 needs-human，不写金额。
"""
from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

# 三家几乎一律 Informative / P5 / N/A 的形态（证据过闸门也不该交）
NA_KINDS = {
    "missing-header",
    "missing_headers",
    "security-headers",
    "best-practice",
    "best_practice",
    "tls-hardening",
    "cookie-flags",
    "version-disclosure",
    "fingerprint",
    "self-xss",
    "self_xss",
    "username-enum",
    "user-enum",
    "email-enum",
    "captcha-echo",
    "captcha",
    "rate-limit",
    "clickjacking",
    "cors-wildcard",
}

# 无资金/权限时，输入校验松通常 N/A
WEAK_LOGIC_HINTS = (
    "rating",
    "score out of range",
    "评分",
    "captcha answer",
    "回显 answer",
)

SEV_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# 证据形态能撑到的最高声称严重度（再高 = 夸大）
KIND_CEILING = {
    "info-disclosure": "low",
    "info_disclosure": "low",
    "information-disclosure": "low",
    "missing-header": "none",
    "best-practice": "none",
    "self-xss": "none",
    "xss": "medium",
    "csrf": "medium",
    "open-redirect": "low",
    "business-logic": "medium",
    "business_logic": "medium",
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").strip().lower()).strip("-")


def pack_hosts(pack: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for c in pack.get("cases") or []:
        url = (c.get("url") or "") if isinstance(c, dict) else ""
        if not url and isinstance(c, dict):
            url = ((c.get("request") or {}).get("url") or "")
        host = (urlparse(url).hostname or "").lower()
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def pack_paths(pack: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for c in pack.get("cases") or []:
        url = (c.get("url") or "") if isinstance(c, dict) else ""
        p = urlparse(url).path or ""
        if p and p not in paths:
            paths.append(p)
    return paths


def path_prefixes(path: str) -> list[str]:
    """ /api/Users/37 → /api/Users/37, /api/Users, /api

    短路径（/ftp、/api、/v1、/sso）必须保留：SRC 里最高频的正是这类，
    过滤掉它们等于让判重对最常见的场景全部失灵。
    只丢弃根路径 '/' 与空串。

    归一化（缺一项就会漏判重）：
      - 去掉 query / fragment：/ftp?x=1 与 /ftp 是同一个资源
      - 去掉 URL 编码：/f%74p 与 /ftp 相同
      - 折叠 // 与 /./：//ftp、/./ftp 都指向 /ftp
      - 保留大小写不敏感比较由调用方处理，这里统一小写
    """
    from urllib.parse import unquote, urlsplit

    raw = (path or "").strip()
    if not raw:
        return []
    # 可能是完整 URL
    if "://" in raw:
        try:
            raw = urlsplit(raw).path or "/"
        except Exception:
            pass
    else:
        raw = raw.split("#", 1)[0].split("?", 1)[0]
    try:
        raw = unquote(raw)
    except Exception:
        pass
    # 折叠 //、/./、/../
    segs: list[str] = []
    for seg in raw.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    raw = "/" + "/".join(segs)
    raw = raw.lower()

    out: list[str] = []
    p = raw.rstrip("/") or "/"
    while p and p not in ("/", ""):
        if len(p) >= 2 and p not in out:
            out.append(p)
        nxt = p.rsplit("/", 1)[0]
        if nxt == p:
            break
        p = nxt
    return out


def claimed_too_high(claimed: str, ceiling: str) -> bool:
    c = SEV_RANK.get((claimed or "").strip().lower(), -1)
    m = SEV_RANK.get((ceiling or "").strip().lower(), 4)
    if c < 0:
        return False
    return c > m


# 证据形态 → 允许的最高声称严重度。
# 关键改动：不再按「漏洞类型」一刀切（那会把 .git 泄露生产密码压成 low），
# 而是看证据里出现了什么后果。命中越重的形态，天花板越高。
# 匹配顺序：从高到低，第一个命中即生效。
IMPACT_CEILING = (
    # 凭据/密钥/管理面被实际取得 → 可到 critical
    (
        ("critical", "high"),
        (
            "rce", "remote code execution", "命令执行", "代码执行",
            "iam credential", "sts:getcalleridentity", "aws_secret_access_key",
            "aws access key", "private key", "私钥", "root password",
            "database password", "db password", "生产库密码", "prod password",
            "admin token", "管理员 token", "admin impersonation", "管理员冒充",
            "alg=none", "auth bypass", "认证绕过", "登录绕过",
            "full account takeover", "账号接管", "takeover",
            "arbitrary file write", "任意文件写入", "任意文件读取",
            "ssrf to metadata", "169.254.169.254",
        ),
    ),
    # 批量 PII / 跨租户 / 可写他人数据 / 管理面被攻陷 → 可到 high
    (
        ("high",),
        (
            "pii", "personal data", "个人数据", "个人信息",
            "million", "万条", "万用户", "full dump", "全量",
            "ssn", "passport", "身份证", "credit card", "信用卡",
            "phone number", "address", "addresses", "医疗", "health record",
            "cross-tenant", "跨租户", "other tenant", "其他租户",
            "any user", "任意用户", "all users", "所有用户",
            "read other", "write other", "delete other", "他人",
            "invoice", "发票", "订单", "order history",
            "admin panel", "管理员面板", "admin dashboard", "管理后台",
            "privilege escalation", "提权", "internal network", "内网访问",
            "financial loss", "资金损失", "payment bypass", "支付绕过",
        ),
    ),
    # 单个用户的敏感数据 / 有实际业务损失 → medium
    (
        ("medium",),
        (
            "credential", "凭据", "token leak", "token 泄露", "api key",
            "password hash", "密码哈希", "session", "会话",
            "confidential", "机密", "内部文档", "internal document",
            "free purchase", "免费", "coupon", "优惠券",
            "stored xss", "存储型 xss", "dom xss",
        ),
    ),
    # 仅有信息暴露、无敏感内容 → low
    (
        ("low",),
        (
            "directory listing", "目录列表", "version", "版本",
            "fingerprint", "指纹", "stack trace", "错误栈",
            "internal path", "内部路径", "source map",
        ),
    ),
)

# 三家几乎一律 N/A 的形态：与后果无关，直接压到 do-not-submit
NA_IMPACT = (
    "missing csp", "missing hsts", "missing x-frame", "缺少安全头",
    "self-xss", "self xss", "自 xss",
    "username enumeration", "用户枚举",
    "captcha echo", "回显 answer",
    "clickjacking", "点击劫持",
    "cors wildcard", "cors 通配",
    "tls 1.0", "weak cipher", "弱加密套件",
    "cookie without", "cookie 缺",
    "banner grabbing", "版本号暴露",
)


def impact_ceiling(kind: str, text: str) -> str | None:
    """按证据形态给天花板。返回 None 表示没有可识别的后果描述。

    这是对 KIND_CEILING 的覆盖层：KIND_CEILING 只作为「无法识别后果」时的兜底。
    IMPACT_CEILING 已按严重度从高到低排列，第一个命中的分组即结论。
    """
    blob = (text or "").lower()
    if not blob.strip():
        return None
    for levels, words in IMPACT_CEILING:
        if any(_affirmed(blob, w) for w in words):
            return levels[0]
    return None


# 否定词：出现在命中短语前一小段内，说明报告是在否认这个后果。
_NEGATORS = (
    "no ", "not ", "cannot ", "can not ", "can't ", "could not ", "unable to ",
    "never ", "without ", "无法", "不能", "不会", "未能", "并未", "没有", "无法读取",
)


def _affirmed(blob: str, phrase: str) -> bool:
    """短语在文中出现且不是被否定的那一处。

    旧实现是裸子串匹配，于是「no account takeover is possible; only a static
    directory listing」被判成 critical、「we could not read other users' data」
    被判成 high —— 反向证据反而把天花板抬高。
    """
    start = 0
    while True:
        i = blob.find(phrase, start)
        if i < 0:
            return False
        window = blob[max(0, i - 40):i]
        if not any(n in window for n in _NEGATORS):
            return True
        start = i + len(phrase)


def _is_na_form(text: str) -> bool:
    blob = (text or "").lower()
    return any(w in blob for w in NA_IMPACT)


def submit_ceiling(kind: str, summary: str, lab: bool) -> str:
    """do-not-submit | low | medium | high | critical | needs-human

    返回的是「最多能说到哪一档」，不是赏金。
    判定顺序：
      1) 靶场 → do-not-submit
      2) 三家 N/A 形态 → do-not-submit
      3) 证据里可识别的后果 → 按后果给档（IMPACT_CEILING）
      4) 无法识别后果 → 退回按漏洞类型的保守兜底（KIND_CEILING）
      5) 类型也不认识 → needs-human
    """
    if lab:
        return "do-not-submit"
    k = _norm(kind)
    blob = f"{k} {(summary or '').lower()}"
    if k in NA_KINDS or _is_na_form(blob):
        return "do-not-submit"
    if k in ("business-logic", "business_logic") and any(h in blob for h in WEAK_LOGIC_HINTS):
        return "do-not-submit"

    impact = impact_ceiling(k, summary)
    if impact:
        return impact

    if k in KIND_CEILING:
        cap = KIND_CEILING[k]
        if cap == "none":
            return "do-not-submit"
        return cap
    return "needs-human"


class DuplicateLookupUnavailable(RuntimeError):
    """判重数据源不可用。

    「查不到」和「没有重复」是两件事：旧实现两者都返回 []，于是数据库连不上时
    判重闸门直接放行（fail-open），重复上报仍会被当成首次提交。调用方必须把
    这个异常当成「无法判定」，按需要人工处理的方式处置。
    """


def lookup_task_duplicates(
    task_id: str = "",
    kind: str = "",
    hosts: list[str] | None = None,
    paths: list[str] | None = None,
    _rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """本平台同任务疑似重复：同 vulnclass + 路径/host 重叠。不是三家 duplicate。"""
    rows = _rows
    if rows is None:
        if not task_id:
            raise DuplicateLookupUnavailable("缺少 task_id，无法判重")
        try:
            import psycopg2  # type: ignore
        except Exception as e:
            raise DuplicateLookupUnavailable(f"psycopg2 不可用（{e.__class__.__name__}）") from e
        dsn = os.environ.get("ARTEX_PG_DSN")
        if not dsn:
            raise DuplicateLookupUnavailable("未配置 ARTEX_PG_DSN")
        try:
            conn = psycopg2.connect(dsn)
            cur = conn.cursor()
            cur.execute(
                "SELECT id, vulnclass, severity, left(coalesce(summary,''), 180), left(coalesce(name,''), 80) "
                "FROM findings WHERE task_id = %s ORDER BY id",
                (int(task_id),),
            )
            rows = [
                {"id": r[0], "vulnclass": r[1] or "", "severity": r[2] or "", "summary": r[3] or "", "name": r[4] or ""}
                for r in cur.fetchall()
            ]
            cur.close()
            conn.close()
        except Exception as e:
            raise DuplicateLookupUnavailable(f"判重查询失败（{e.__class__.__name__}: {e}）") from e
    k = _norm(kind)
    hosts = [h.lower() for h in (hosts or []) if h]
    paths = [p for p in (paths or []) if p]
    # 判重用的前缀：不再按长度丢弃短路径。/ftp、/api、/v1、/sso 必须参与匹配。
    prefixes: list[str] = []
    for p in paths:
        prefixes.extend(path_prefixes(p))
    prefixes = [x for x in dict.fromkeys(p.lower() for p in prefixes) if len(x) >= 2]
    hits: list[dict[str, Any]] = []
    for row in rows:
        rk = _norm(str(row.get("vulnclass") or ""))
        if k and rk and k != rk:
            continue
        text = f"{row.get('summary') or ''} {row.get('name') or ''}".lower()
        # 路径命中要区分「一级泛化容器」和「一级具体资源」：
        #   /ftp          → 一级但具体，独立出现即可算命中
        #   /rest、/api、/v1 → 一级泛化容器，只有独立成 token 才算
        #     （否则 /rest/products 会因 finding 里出现 /rest/user/login 而误报）
        # 二级及以上前缀（/rest/products、/api/users/37）按子串匹配，足够具体。
        path_hit = False
        for pref in prefixes:
            depth = len([s for s in pref.split("/") if s])
            if depth >= 2:
                if pref in text:
                    path_hit = True
                    break
            else:
                # 一级：必须是独立 token，前后不能紧邻路径字符
                if re.search(r"(?<![\w/])" + re.escape(pref) + r"(?![\w/-])", text):
                    path_hit = True
                    break
        host_hit = any(h in text for h in hosts if h not in ("localhost", "127.0.0.1"))
        same_class = bool(k and rk and k == rk)
        # 命中条件（任一）：
        #   1) 路径前缀重叠（含短路径 /ftp、/api、/v1）
        #   2) host 重叠且同 vulnclass
        # 刻意保留「同类但完全对不上路径/host 时不报」：
        # 否则所有 IDOR 都会被列成互相的重复候选，噪音大到没人看。
        if not (path_hit or (host_hit and same_class)):
            continue
        hits.append(
            {
                "finding_id": row.get("id"),
                "vulnclass": row.get("vulnclass"),
                "severity": row.get("severity"),
                "summary": row.get("summary"),
                "match": (
                    "path" if path_hit else ("host+class" if host_hit and same_class else "class-only")
                ),
            }
        )
    # 路径命中的排前面：它们最可能是同一缺陷
    hits.sort(key=lambda h: {"path": 0, "host+class": 1, "class-only": 2}.get(str(h.get("match")), 3))
    return hits[:8]


def brief(
    *,
    lab: bool,
    gate_ok: bool,
    recommended: str,
    kind: str = "",
    title: str = "",
    impact: str = "",
    claimed_severity: str = "",
    task_id: str = "",
    pack: dict[str, Any] | None = None,
    _dup_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    pack = pack or {}
    hosts = pack_hosts(pack)
    paths = pack_paths(pack)
    ceiling = submit_ceiling(kind, f"{title} {impact}", lab)
    dup_error = ""
    try:
        dups = lookup_task_duplicates(task_id, kind, hosts, paths, _rows=_dup_rows)
    except DuplicateLookupUnavailable as e:
        dups, dup_error = [], str(e)
    too_high = claimed_too_high(claimed_severity, ceiling if ceiling not in ("do-not-submit", "needs-human") else "high")
    if ceiling == "do-not-submit":
        too_high = claimed_too_high(claimed_severity, "none") or too_high

    if lab or ceiling == "do-not-submit" or not gate_ok or recommended in ("not_a_vuln", "inconclusive"):
        action = "do-not-submit"
    elif dups or dup_error or too_high or ceiling == "needs-human":
        action = "needs-human"
    else:
        action = "maybe-submit"

    reasons: list[str] = []
    if lab:
        reasons.append("靶场/内网：禁止交三家")
    if ceiling == "do-not-submit" and not lab:
        reasons.append("三家常见 N/A 或无安全影响（缺安全头/self-XSS/无资金的输入校验等）")
    if not gate_ok:
        reasons.append("闸门未过：不能当洞交")
    if dups:
        reasons.append("本任务已有同类同路径记录，先核对是不是重复")
    if dup_error:
        reasons.append(f"判重无法完成（{dup_error}）：按「可能重复」处理，不要直接提交")
    if too_high:
        reasons.append(f"声称严重度 {claimed_severity} 高于证据形态上限 {ceiling}，按夸大处理")
    if ceiling == "needs-human" and action == "needs-human" and gate_ok:
        reasons.append("技术上可能成立，赏金/政策/跨平台重复需要你自己看")

    return {
        "submit_action": action,
        "severity_ceiling": ceiling,
        "price": None,
        "price_note": "机器不标价、不猜赏金表。",
        "duplicate_in_task": dups,
        "duplicate_check_error": dup_error,
        "claimed_too_high": too_high,
        "reasons": reasons,
    }
