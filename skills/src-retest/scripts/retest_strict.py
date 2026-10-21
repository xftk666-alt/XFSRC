#!/usr/bin/env python3
"""独立复测硬闸门 v2：现场重算 + HMAC 封印，不信任磁盘上的 gate.json。

preview  人眼摘录
gate     重读 body + 验 seal，写出 *签名* gate.json
verdict  忽略手写 gate.json，现场 evaluate；reproduced 必须 live ok
signoff  口令必须带 gate.challenge；文档 HMAC；现场仍须 ok
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from evidence_seal import (  # noqa: E402
    audit,
    case_age_sec,
    sign_document,
    verify_case,
    verify_document,
    verify_pack,
    verify_pack_cases,
)

PLACEHOLDER = re.compile(r"^\{[a-zA-Z0-9_]+\}$")
GENERIC = {
    "true",
    "false",
    "success",
    "error",
    "ok",
    "data",
    "status",
    "null",
    "undefined",
    "user",
    "admin",
    "id",
    "email",
    "name",
    "token",
    "message",
    "object",
    "array",
    "customer",
    "200",
    "401",
    "403",
    "404",
    "role",
    "users",
    "item",
    "items",
    "result",
    "results",
    "html",
    "doctype",
    "index",
    "welcome",
    "home",
    "login",
    "password",
    "username",
    "authorization",
    "bearer",
    "application/json",
    "text/html",
    "charset",
    "utf-8",
    "content-type",
    "javascript",
    "value",
    "type",
    "code",
    "uuid",
}
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
SIGNOFF_PHRASES = (
    "I inspected the evidence pack and approve submit",
    "我已核验证据包并批准提交",
)
RECORDER_UA = "artex-http-evidence/1.0"
EXCERPT_PAD = 80
FIELD_CHECK_NAMES = {
    "attack_contains",
    "control_not_contains",
    "json_path_differs",
    "attack_json_value",
}
IDOR_KINDS = {"idor", "bola", "vertical", "bfla", "idor-write"}
AUTH_HEADER_RE = re.compile(r"(?im)^Authorization:\s*Bearer\s+(\S+)")
COOKIE_TOKEN_RE = re.compile(r"(?i)(?:^Cookie:.*?;|\s|^Cookie:\s*)token=([^;\s]+)")
JWT_LIKE_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
MAX_CASE_AGE_SEC = int(os.environ.get("ARTEX_EVIDENCE_MAX_AGE_SEC", str(2 * 60 * 60)))
MAX_JWT_AGE_SEC = MAX_CASE_AGE_SEC
# iat 由目标服务器生成，与本机存在秒级时钟偏差时不应误判为「未来 token」
JWT_CLOCK_SKEW_SEC = 300


def empty(v: str | None) -> bool:
    if v is None:
        return True
    v = str(v).strip()
    return (not v) or bool(PLACEHOLDER.match(v)) or v.lower() in ("none", "null", "-")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
        f.write("\n")


def load_pack(outdir: str) -> dict[str, Any]:
    path = os.path.join(outdir, "pack.json")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return load_json(path)


def file_sha256(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pack_fingerprint(outdir: str) -> str:
    parts: list[str] = []
    pack_path = os.path.join(outdir, "pack.json")
    parts.append("pack:" + (file_sha256(pack_path) or "missing"))
    cases_dir = os.path.join(outdir, "cases")
    if os.path.isdir(cases_dir):
        for name in sorted(os.listdir(cases_dir)):
            body = os.path.join(cases_dir, name, "response.body")
            shot = os.path.join(cases_dir, name, "screenshot.png")
            seal = os.path.join(cases_dir, name, "seal.json")
            if os.path.isfile(body):
                parts.append(f"body:{name}:{file_sha256(body)}")
            if os.path.isfile(shot):
                parts.append(f"shot:{name}:{file_sha256(shot)}")
            if os.path.isfile(seal):
                parts.append(f"seal:{name}:{file_sha256(seal)}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def is_lab(pack: dict[str, Any]) -> bool:
    """靶场判定：委托 lab_detect（网段/后缀/单标签/FQDN 规则）。

    只认结构化 host。旧实现还留了一层 LAB_HINTS 子串兜底，于是 SSRF 证据里
    `?url=http://127.0.0.1:8080/admin` 这种**攻击载荷**会把真实公网资产判成
    靶场，导致 legitimate 发现永远 submit_advice=never（审计发现的误报）。
    """
    try:
        from lab_detect import is_lab as _detect

        return bool(_detect(pack))
    except Exception:
        # 判定器不可用时按「无法判定」处理：宁可让闸门继续用其它证据，也不要
        # 用子串猜测把一个真实资产打成靶场。
        return False


def is_lab_sealed(outdir: str, pack: dict[str, Any]) -> bool:
    """lab 判定同时看封印内容：改 pack.json 不能把靶场洗成真实资产。"""
    if is_lab(pack):
        return True
    path = os.path.join(outdir, "pack.seal.json")
    if os.path.isfile(path):
        try:
            doc = load_json(path)
            payload = doc.get("payload") or {}
            try:
                from lab_detect import is_lab as _detect

                if _detect(payload):
                    return True
            except Exception:
                pass
            # 不再对 payload 做自由文本子串扫描：SSRF 的 `?url=http://127.0.0.1/`
            # 会把真实公网资产误判成靶场（审计发现的误报）。
        except Exception:
            pass
    # request.txt 是「攻击载荷」而不是资产地址：SSRF 证据里出现
    # `?url=http://127.0.0.1:8080/admin` 不代表被测资产是靶场，按它判定会把
    # 真实公网资产的 SSRF 全部误判成 lab（审计发现的误报）。资产身份只看
    # pack / pack.seal 的结构化 url 字段。
    return False


def read_body(outdir: str, name: str) -> bytes:
    path = os.path.join(outdir, "cases", name, "response.body")
    if not os.path.isfile(path):
        return b""
    with open(path, "rb") as f:
        return f.read()


def excerpt_around(raw: bytes, needle: str, pad: int = EXCERPT_PAD) -> str | None:
    b = needle.encode("utf-8", "replace")
    i = raw.find(b)
    if i < 0:
        return None
    a = max(0, i - pad)
    c = min(len(raw), i + len(b) + pad)
    chunk = raw[a:c].decode("utf-8", "replace").replace("\n", "\\n")
    return f"...{chunk}..."


def marker_ok(marker: str) -> str | None:
    m = (marker or "").strip()
    if empty(m):
        return "victim_marker 必填（受害者邮箱 / UserId 长串 / 机密片段 / dialog.message）"
    if len(m) < 8 and "@" not in m:
        return "victim_marker 太短且不像邮箱：禁止用 200/id/ok 这种泛词。IDOR 请用 B 的邮箱或 ≥8 位唯一串"
    if m.lower() in GENERIC:
        return f"victim_marker 过于泛化: {m}"
    if PLACEHOLDER.match(m):
        return "victim_marker 是占位符"
    return None


def case_names(pack: dict[str, Any]) -> list[str]:
    return [c.get("name") or "" for c in pack.get("cases") or []]


def pick_case(pack: dict[str, Any], name: str, prefixes: tuple[str, ...]) -> str | None:
    if not empty(name):
        return name.strip()
    names = case_names(pack)
    for n in names:
        if any(n.startswith(p) for p in prefixes):
            return n
    xss = [c.get("name") for c in pack.get("cases") or [] if c.get("kind") == "browser-xss"]
    if xss and "xss" in prefixes:
        return xss[0]
    return None


def load_meta(outdir: str, name: str) -> dict[str, Any]:
    path = os.path.join(outdir, "cases", name, "meta.json")
    if not os.path.isfile(path):
        return {}
    try:
        return load_json(path)
    except Exception:
        return {}


def read_request_txt(outdir: str, name: str) -> str:
    path = os.path.join(outdir, "cases", name, "request.txt")
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def origin_of(url: str) -> str:
    p = urlparse(url or "")
    if not p.scheme or not p.netloc:
        return ""
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return ""
    try:
        port = p.port
    except ValueError:
        port = None
    scheme = p.scheme.lower()
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}"


def b64url_decode(seg: str) -> bytes:
    pad = "=" * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode((seg + pad).encode("ascii"))


def jwt_iat(token: str) -> int | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None
    iat = payload.get("iat")
    if isinstance(iat, (int, float)):
        return int(iat)
    return None


def extract_bearer(request_txt: str) -> str | None:
    m = AUTH_HEADER_RE.search(request_txt or "")
    if m:
        return m.group(1).strip()
    m = COOKIE_TOKEN_RE.search(request_txt or "")
    if m:
        return m.group(1).strip()
    return None


def auth_fingerprint(request_txt: str) -> str | None:
    tok = extract_bearer(request_txt)
    if not tok:
        return None
    return hashlib.sha256(tok.encode("utf-8", "replace")).hexdigest()


def is_self_control_name(name: str) -> bool:
    n = (name or "").lower()
    if re.search(r"(^|-)(self|own|me)(-|$)", n):
        return True
    if re.search(r"(^|-)(control-a|attacker-a)(-|$)", n) or n in ("control-a", "attacker-a"):
        return True
    return False


def is_unauth_control_name(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in ("unauth", "notoken", "no-token", "anonymous", "logged-out"))


def _marker_forms(marker: str) -> set[str]:
    """明文 + 一层/两层 URL 编码（含 + 空格）以及 HTML 实体。"""
    from urllib.parse import quote, quote_plus
    import html as html_mod

    forms = {marker}
    cur = {marker}
    for _ in range(2):
        nxt: set[str] = set()
        for item in cur:
            nxt.add(quote(item, safe=""))
            nxt.add(quote_plus(item, safe=""))
        forms |= nxt
        cur = nxt
    forms.add(html_mod.escape(marker, quote=True))
    forms.add(marker.replace("@", "&#64;").replace(".", "&#46;"))
    forms.discard("")
    return forms


def request_contains_marker(request_txt: str, marker: str) -> bool:
    """marker 是否出现在「客户端自己发出去的请求」里（=回显，不是读到了别人的数据）。

    覆盖一层/两层 URL 编码、+ 空格、HTML 实体，以及请求行/请求体解码后再比对。
    不看 Authorization / Cookie，避免把 token 里的偶然子串当成回显。
    """
    if not marker or not request_txt:
        return False
    from urllib.parse import unquote, unquote_plus

    kept: list[str] = []
    for line in request_txt.splitlines():
        low = line.lower()
        if low.startswith("authorization:") or low.startswith("cookie:"):
            continue
        kept.append(line)
    blob = "\n".join(kept)
    decoded = blob
    try:
        once = unquote_plus(unquote(blob))
        decoded = unquote_plus(unquote(once))
    except Exception:
        decoded = blob
    forms = _marker_forms(marker)
    for form in forms:
        if form and (form in blob or form in decoded):
            return True
    # 请求里先解码再和明文比（双编码回显）
    if marker in decoded:
        return True
    return False


def effective_kind(declared: str, pack: dict[str, Any], is_xss: bool) -> tuple[str, list[str]]:
    """不信 agent 自报的 kind：按证据形态升级。

    只要包里出现「同一会话读自己对象」的对照、或无 token 对照，
    就必须按 IDOR/越权标准审查，避免把 kind 改成 http 绕过 control-self。
    """
    notes: list[str] = []
    k = (declared or "").strip().lower()
    if is_xss:
        return "xss", notes
    has_self = bool(pick_named(pack, is_self_control_name))
    has_unauth = bool(pick_named(pack, is_unauth_control_name))
    if k in IDOR_KINDS:
        return k, notes
    if has_self:
        notes.append(f"declared kind={k or 'empty'} 但存在 control-self：按 idor 标准审查")
        return "idor", notes
    if has_unauth:
        notes.append(f"declared kind={k or 'empty'} 但存在无 token 对照：按 idor 标准审查")
        return "idor", notes
    return k or "http", notes


def pick_named(pack: dict[str, Any], predicate) -> str | None:
    for n in case_names(pack):
        if predicate(n):
            return n
    return None


def spa_sha_set(outdir: str, pack: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for c in pack.get("cases") or []:
        url = c.get("url") or ""
        name = (c.get("name") or "").lower()
        path = urlparse(url).path or "/"
        raw = read_body(outdir, c.get("name") or "")
        sha = hashlib.sha256(raw).hexdigest() if raw else c.get("body_sha256")
        if not sha:
            continue
        if path in ("/", "") or name in ("control-home", "home", "index"):
            out.add(sha)
        head = raw[:200].lower()
        if b"<!doctype html" in head or b"<html" in head:
            low = raw.lower()
            if b"ng-app" in low or b'id="root"' in low or b"app-root" in low:
                if len(raw) < 20000:
                    out.add(sha)
    return out


def compare_asserts_marker(detail: dict[str, Any], marker: str) -> bool:
    for x in detail.get("checks") or []:
        if not x.get("pass"):
            continue
        if x.get("name") in ("attack_contains", "attack_json_value", "control_not_contains"):
            exp = str(x.get("expected") or "")
            if exp == marker or marker in exp:
                return True
    return False


def evaluate(
    outdir: str,
    kind: str = "",
    victim_marker: str = "",
    attack: str = "",
    control: str = "",
) -> dict[str, Any]:
    outdir = os.path.abspath(outdir)
    kind = (kind or "").strip().lower()
    marker = (victim_marker or "").strip()
    checks: list[dict[str, Any]] = []
    reasons: list[str] = []
    recommended = "inconclusive"

    def add(name: str, ok: bool, expected: Any, actual: Any, reason: str = "") -> None:
        checks.append({"name": name, "pass": bool(ok), "expected": expected, "actual": actual})
        if not ok and reason:
            reasons.append(reason)

    try:
        pack = load_pack(outdir)
    except FileNotFoundError as e:
        return {
            "ok": False,
            "verdict_allowed": "inconclusive",
            "recommended_verdict": "inconclusive",
            "submit_advice": "never",
            "reasons": [f"missing pack.json: {e}"],
            "checks": [],
            "lab": True,
            "fingerprint": None,
            "integrity": {"ok": False, "results": []},
            "challenge": None,
            "victim_marker": marker,
            "attack": None,
            "control": None,
            "kind": kind or "http",
            "pack": None,
            "live": True,
        }

    cases = pack.get("cases") or []
    compares = pack.get("compares") or []
    xss_cases = [c for c in cases if c.get("kind") == "browser-xss" or c.get("dialog_executed") is not None]
    is_xss = kind == "xss" or bool(xss_cases)
    # kind 由证据形态决定，不接受 agent 自报降级
    kind, kind_notes = effective_kind(kind, pack, is_xss)
    is_xss = kind == "xss"
    lab = is_lab_sealed(outdir, pack)
    attack_n = pick_case(pack, attack, ("attack", "xss"))
    control_n = pick_case(pack, control, ("control",))

    # pack.json 也被封印：防止改写 url 把靶场证据伪装成真实资产（或反过来）
    pack_ok, pack_why = verify_pack(outdir)
    add("pack_sealed", pack_ok, "signed pack.seal.json", pack_why, f"pack.json 未封印或被改写：{pack_why}")
    for n in kind_notes:
        add("kind_from_evidence", True, "evidence-derived kind", n)

    integrity = verify_pack_cases(outdir)
    add("integrity_seals", bool(integrity.get("ok")), True, integrity.get("results"), "存在未封印或被篡改的 case（禁止手写 response.body）")
    if not integrity.get("ok"):
        recommended = "inconclusive"

    add("has_cases", bool(cases), True, len(cases), "没有落盘 case")

    # 证据时效：复测要验证「当前状态」，旧包不能冒充今天的复测
    ages = []
    for n in [attack_n, control_n] + [x for x in case_names(pack) if is_self_control_name(x) or is_unauth_control_name(x)]:
        if not n:
            continue
        a = case_age_sec(os.path.join(outdir, "cases", n))
        if a is not None:
            ages.append({"case": n, "age_sec": int(a)})
    if ages:
        fresh = all(0 <= x["age_sec"] <= MAX_CASE_AGE_SEC for x in ages)
        add(
            "evidence_fresh",
            fresh,
            f"all cases recorded within {MAX_CASE_AGE_SEC}s",
            ages,
            "证据不是本次会话新录的（超过时效）：不能用来证明「当前仍然存在」。请重新 http_evidence_record",
        )
        if not fresh:
            recommended = "inconclusive"
    else:
        add("evidence_fresh", False, "case ts present", None, "case 缺 ts，无法确认是本次复测")

    if is_xss:
        executed = any(c.get("dialog_executed") for c in xss_cases)
        add("dialog_executed", executed, True, executed, "XSS 必须 browser_xss_evidence 且 dialog_executed=true")
        shot_ok_any = False
        for c in xss_cases:
            cdir = c.get("dir") or os.path.join(outdir, "cases", c.get("name") or "")
            shot = os.path.join(cdir, "screenshot.png")
            if c.get("dialog_executed"):
                png = False
                size = os.path.getsize(shot) if os.path.isfile(shot) else 0
                if size > 32:
                    try:
                        with open(shot, "rb") as sf:
                            png = sf.read(8) == b"\x89PNG\r\n\x1a\n"
                    except Exception:
                        png = False
                shot_ok_any = shot_ok_any or png
                add(
                    "screenshot_png",
                    png,
                    "PNG signature and size>32",
                    {"path": shot, "size": size, "png": png},
                    "XSS 必须有真实 PNG 截图（缺文件、过小或不是 PNG 都不算）",
                )
            ok_s, why = verify_case(cdir)
            add(f"seal:{c.get('name')}", ok_s, "valid seal", why, why if not ok_s else "")
        if executed and not shot_ok_any:
            recommended = "inconclusive"
        dialog_msgs = []
        for c in xss_cases:
            for d in c.get("dialogs") or []:
                if d.get("message"):
                    dialog_msgs.append(str(d.get("message")))
        err = marker_ok(marker) if marker else "XSS 也必须提供 dialog.message 作为 victim_marker"
        if err:
            add("marker_shape", False, "unique marker", marker, err)
        else:
            in_dialog = any(marker in m for m in dialog_msgs)
            add(
                "marker_in_dialog",
                in_dialog,
                marker,
                dialog_msgs,
                "XSS victim_marker 必须出现在 dialog.message（通常是 document.domain），禁止只用 innerHTML",
            )
        if not executed:
            recommended = "not_a_vuln"
    else:
        err = marker_ok(marker)
        add("marker_shape", err is None, "unique ≥8 or email", marker, err or "")
        add("attack_named", bool(attack_n), "attack-*", attack_n, "缺少 attack case")
        add("control_named", bool(control_n), "control-*", control_n, "缺少 control case")
        a_req = read_request_txt(outdir, attack_n) if attack_n else ""
        a_meta = load_meta(outdir, attack_n) if attack_n else {}
        c_meta = load_meta(outdir, control_n) if control_n else {}

        if attack_n:
            a_body = read_body(outdir, attack_n)
            a_dir = os.path.join(outdir, "cases", attack_n)
            a_path = os.path.join(a_dir, "response.body")
            add("attack_body_file", os.path.isfile(a_path) and os.path.getsize(a_path) > 0, a_path, os.path.isfile(a_path), "缺少 attack response.body")
            ok_s, why = verify_case(a_dir)
            add("attack_seal", ok_s, "valid seal", why, why if not ok_s else "")
            ua = ((a_meta.get("request") or {}).get("headers_redacted") or {}).get("User-Agent")
            add("recorded_by_tool", ua == RECORDER_UA, RECORDER_UA, ua, "attack 不是 http_evidence_record 记下的")
            if marker and err is None:
                has = marker.encode("utf-8") in a_body
                add(
                    "attack_has_victim_marker",
                    has,
                    marker,
                    excerpt_around(a_body, marker) or "ABSENT",
                    "attack 正文没有受害者/机密字段。HTTP 200 不算洞",
                )
                if not has:
                    recommended = "not_a_vuln"
                echo = request_contains_marker(a_req, marker)
                add(
                    "marker_not_echoed_from_request",
                    not echo,
                    "marker 不得出现在 attack 的 URL/请求体（排除 Authorization/Cookie）",
                    "ECHO" if echo else "ok",
                    "victim_marker 出现在请求里：多半是参数回显，不是读到了别人的数据",
                )
                if echo:
                    recommended = "not_a_vuln"
        if control_n:
            c_body = read_body(outdir, control_n)
            c_dir = os.path.join(outdir, "cases", control_n)
            c_path = os.path.join(c_dir, "response.body")
            add("control_body_file", os.path.isfile(c_path), c_path, os.path.isfile(c_path), "缺少 control response.body")
            ok_s, why = verify_case(c_dir)
            add("control_seal", ok_s, "valid seal", why, why if not ok_s else "")
            if marker and err is None:
                c_has = marker.encode("utf-8") in c_body
                add(
                    "control_lacks_victim_marker",
                    not c_has,
                    f"ABSENT {marker}",
                    excerpt_around(c_body, marker) or "ABSENT",
                    "对照包里也有同一 marker：没有证明跨过安全边界（可能是自己的数据或公开页）",
                )
                if c_has:
                    recommended = "not_a_vuln"
        if attack_n and control_n:
            a_raw = read_body(outdir, attack_n)
            c_raw = read_body(outdir, control_n)
            a_sha = hashlib.sha256(a_raw).hexdigest()
            c_sha = hashlib.sha256(c_raw).hexdigest()
            add("bodies_differ", a_sha != c_sha, True, {"attack": a_sha, "control": c_sha}, "attack 与 control 正文相同")
            spa = spa_sha_set(outdir, pack)
            if a_sha in spa:
                add("not_spa_fallback", False, "attack sha != homepage", a_sha, "SPA fallback：攻击路径正文与首页相同，不是信息泄露")
                recommended = "not_a_vuln"
            a_url = ((a_meta.get("request") or {}).get("url") or "")
            c_url = ((c_meta.get("request") or {}).get("url") or "")
            a_origin = origin_of(a_url)
            c_origin = origin_of(c_url)
            same_origin = bool(a_origin) and a_origin == c_origin
            add(
                "same_origin",
                same_origin,
                a_origin,
                {"attack": a_origin, "control": c_origin},
                "attack 与 control 必须打同一个 origin。禁止用本地假服务/另一台主机凑对照",
            )
            if not same_origin:
                recommended = "inconclusive"
            # IDOR/越权：control-self 也必须和 attack 同一个 origin，不能换一台主机凑「自己的对象」
            if kind in IDOR_KINDS:
                self_n_early = pick_named(pack, is_self_control_name)
                if self_n_early:
                    s_meta_early = load_meta(outdir, self_n_early)
                    s_url_early = ((s_meta_early.get("request") or {}).get("url") or "")
                    s_origin = origin_of(s_url_early)
                    self_same = bool(a_origin) and a_origin == s_origin
                    add(
                        "control_self_same_origin",
                        self_same,
                        a_origin,
                        {"attack": a_origin, "self": s_origin},
                        "control-self 与 attack 不是同一个 origin：禁止换主机凑「自己的对象」",
                    )
                    if not self_same:
                        recommended = "inconclusive"

        # JWT 必须是本会话新签的：禁止复用开洞 worker 落盘的旧 token
        if attack_n:
            tok = extract_bearer(a_req)
            if tok and JWT_LIKE_RE.match(tok):
                iat = jwt_iat(tok)
                ts = a_meta.get("ts") or ""
                try:
                    case_epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() if ts else time.time()
                except Exception:
                    case_epoch = time.time()
                if iat is None:
                    add(
                        "jwt_has_iat_or_not_jwt",
                        True,
                        "no iat (allowed)",
                        None,
                    )
                else:
                    age = case_epoch - iat
                    # 允许小幅时钟偏差（服务端 iat 可能比本机 record 时间早/晚数秒）
                    fresh = -JWT_CLOCK_SKEW_SEC <= age <= MAX_JWT_AGE_SEC
                    add(
                        "jwt_fresh",
                        fresh,
                        f"iat within {MAX_JWT_AGE_SEC}s of record",
                        {"iat": iat, "age_sec": int(age)},
                        "JWT iat 过旧或在未来：禁止复用开洞 worker 的旧 token，必须本会话新登录",
                    )
                    if not fresh:
                        recommended = "inconclusive"

        field_compares = []
        marker_in_named = False
        named_field_pass = False
        for comp in compares:
            f = comp.get("file")
            # compare-*.json 不参与 HMAC：只把它当「声明」，用封印后的 case 复算；
            # pass 只认 pack.seal.json 覆盖的 comp["pass"]。
            verified, has_field, marker_bound, why = verify_compare_claims(
                outdir, comp, attack_n, control_n, marker
            )
            sealed_pass = comp.get("pass") is True
            pair_match = (comp.get("attack") == attack_n and comp.get("control") == control_n)
            if pair_match and sealed_pass and verified and has_field:
                named_field_pass = True
                if marker:
                    marker_in_named = marker_in_named or marker_bound
            field_compares.append(
                {
                    "file": f,
                    "pass": sealed_pass,
                    "verified": verified,
                    "has_field_assert": has_field,
                    "marker_bound": marker_bound,
                    "checks": why,
                    "pair_match": pair_match,
                    "attack": comp.get("attack"),
                    "control": comp.get("control"),
                }
            )
        unpaired_good = [
            x
            for x in field_compares
            if x["pass"] is True and x["verified"] and x["has_field_assert"] and not x["pair_match"]
        ]
        status_only = [
            x for x in field_compares if x["pass"] is True and x["verified"] and not x["has_field_assert"]
        ]
        add(
            "field_level_compare",
            named_field_pass,
            f"compare {attack_n} vs {control_n} 含 attack_contains/json_path 且 pass",
            {
                "named_pass": named_field_pass,
                "unpaired": [x["file"] for x in unpaired_good],
                "status_only": [x["file"] for x in status_only],
            },
            "必须对「这次的 attack vs 这次的 control」做字段级对照。拿另一对 case 凑 pass 无效",
        )
        json_only = False
        if named_field_pass:
            for comp in compares:
                if comp.get("attack") != attack_n or comp.get("control") != control_n:
                    continue
                f = comp.get("file")
                detail = {}
                if f and os.path.isfile(f):
                    try:
                        detail = load_json(f)
                    except Exception:
                        detail = {}
                names = {x.get("name") for x in detail.get("checks") or []}
                if detail.get("pass") is True and "json_path_differs" in names:
                    json_only = True
        bound = bool(marker_in_named) or (
            json_only and any(c["name"] == "attack_has_victim_marker" and c["pass"] for c in checks)
        )
        add(
            "compare_uses_victim_marker",
            bound or not named_field_pass,
            marker,
            {"marker_in_named_compare": marker_in_named, "json_only": json_only},
            "compare 的 attack_contains/json 期望值必须就是 victim_marker，禁止用无关字符串凑 pass",
        )
        if named_field_pass and not bound:
            reasons.append("compare 未绑定 victim_marker")
        if status_only and not named_field_pass:
            reasons.append("status-only compare 已忽略")
        if unpaired_good and not named_field_pass:
            reasons.append("存在其它 pair 的 compare，但不能代替 named attack/control")

        # IDOR/越权：必须有「同一会话读自己的对象」对照，挡住「把自己的数据当越权」
        if kind in IDOR_KINDS:
            self_n = pick_named(pack, is_self_control_name)
            add(
                "idor_has_control_self",
                bool(self_n),
                "control-self / control-own / control-me",
                self_n,
                "IDOR 必须另录 control-self：同一 token 读自己的对象。只跟 401 比会把「读到自己的数据」当成洞",
            )
            if self_n and marker and err is None:
                s_body = read_body(outdir, self_n)
                s_has = marker.encode("utf-8") in s_body
                add(
                    "control_self_lacks_victim_marker",
                    not s_has,
                    f"ABSENT {marker}",
                    excerpt_around(s_body, marker) or "ABSENT",
                    "control-self 里也有同一 marker：这是你自己的数据，不是 IDOR",
                )
                if s_has:
                    recommended = "not_a_vuln"
                s_req = read_request_txt(outdir, self_n)
                a_fp = auth_fingerprint(a_req)
                s_fp = auth_fingerprint(s_req)
                same_sess = bool(a_fp) and a_fp == s_fp
                add(
                    "control_self_same_session",
                    same_sess,
                    "attack 与 control-self 同一 Authorization/token",
                    {"attack_auth": a_fp, "self_auth": s_fp},
                    "control-self 必须和 attack 用同一登录会话，只改对象 id",
                )
                s_meta = load_meta(outdir, self_n)
                s_url = ((s_meta.get("request") or {}).get("url") or "")
                a_url = ((a_meta.get("request") or {}).get("url") or "")
                different_object = (s_url.split("?")[0] != a_url.split("?")[0]) if a_url and s_url else True
                add(
                    "control_self_different_object",
                    different_object,
                    "self URL ≠ attack URL",
                    {"attack": a_url, "self": s_url},
                    "control-self 与 attack 是同一 URL：没有换对象 id",
                )
                if not different_object:
                    recommended = "not_a_vuln"
                if not same_sess:
                    recommended = "not_a_vuln"
            unauth_n = pick_named(pack, is_unauth_control_name)
            if not unauth_n:
                add(
                    "idor_has_control_unauth",
                    False,
                    "control-unauth / control-notoken",
                    None,
                    "IDOR/越权必须另录无 token 调同一对象：否则无法排除「这个接口本来就公开」",
                )
                recommended = "not_a_vuln"
            elif marker and err is None:
                u_body = read_body(outdir, unauth_n)
                u_has = marker.encode("utf-8") in u_body
                add(
                    "control_unauth_denied",
                    not u_has,
                    f"无 token 时不得返回 {marker}",
                    excerpt_around(u_body, marker) or "ABSENT",
                    "无 token 也能读到同一份受害者数据：这是公开接口，不是 IDOR/越权",
                )
                if u_has:
                    recommended = "not_a_vuln"

    ok = all(c["pass"] for c in checks) if checks else False
    if lab:
        submit = "never"
        reasons.append("lab/CTF/Juice Shop → 永远不交三家 SRC")
    elif not ok:
        submit = "never"
    else:
        submit = "needs-human"

    if ok:
        recommended = "reproduced"
    elif recommended != "not_a_vuln":
        recommended = "inconclusive"

    fp = pack_fingerprint(outdir)
    # challenge 必须只由「证据状态 + marker」决定：每次 evaluate 现造随机 challenge
    # 会让 signoff 与 verdict 永远对不上（gate 签一个、verdict 现场重算又换一个）。
    # 指纹变了 challenge 自然变。
    challenge = hashlib.sha256(f"{fp}:{marker}:{kind}".encode()).hexdigest()[:12]
    return {
        "ok": ok,
        "verdict_allowed": "reproduced" if ok else recommended,
        "recommended_verdict": recommended,
        "submit_advice": submit,
        "kind": kind or ("xss" if is_xss else "http"),
        "victim_marker": marker,
        "attack": attack_n,
        "control": control_n,
        "lab": lab,
        "fingerprint": fp,
        "challenge": challenge,
        "n_cases": len(cases),
        "n_compares": len(compares),
        "checks": checks,
        "reasons": reasons,
        "integrity": integrity,
        "pack": os.path.join(outdir, "pack.json"),
        "live": True,
        "ts": now(),
        "note": "gate.json 必须带 HMAC。verdict 会现场重算，手改 ok=true 无效。ready 需要口令+challenge。",
    }


def write_signed_gate(outdir: str, live: dict[str, Any]) -> dict[str, Any]:
    payload = {k: v for k, v in live.items() if k not in ("hmac_sha256", "alg", "signed_kind")}
    doc = sign_document("gate", payload)
    dump_json(os.path.join(outdir, "gate.json"), doc)
    audit("gate", outdir=outdir, ok=live.get("ok"), fingerprint=live.get("fingerprint"), challenge=live.get("challenge"))
    # stdout 给人看：顶层带 ok/challenge
    view = dict(payload)
    view["hmac_sha256"] = doc["hmac_sha256"]
    view["signed"] = True
    return view


def cmd_preview(args: argparse.Namespace) -> int:
    if empty(args.outdir):
        print("ERROR: outdir 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    pack = load_pack(outdir)
    attack = pick_case(pack, args.attack, ("attack", "xss"))
    control = pick_case(pack, args.control, ("control",))
    marker = (args.victim_marker or "").strip()
    integrity = verify_pack_cases(outdir)
    result: dict[str, Any] = {
        "outdir": outdir,
        "fingerprint": pack_fingerprint(outdir),
        "attack": attack,
        "control": control,
        "victim_marker": marker,
        "lab": is_lab_sealed(outdir, pack),
        "integrity": integrity,
        "cases": [],
    }
    for c in pack.get("cases") or []:
        name = c.get("name") or ""
        raw = read_body(outdir, name)
        item = {
            "name": name,
            "kind": c.get("kind"),
            "status": c.get("status"),
            "url": c.get("url"),
            "body_len": c.get("body_len") or len(raw),
            "body_sha256": hashlib.sha256(raw).hexdigest() if raw else c.get("body_sha256"),
            "dialog_executed": c.get("dialog_executed"),
            "dialogs": c.get("dialogs"),
            "marker_present": (marker.encode() in raw) if marker and raw else False,
            "marker_excerpt": excerpt_around(raw, marker) if marker else None,
            "body_head": raw[:300].decode("utf-8", "replace"),
        }
        result["cases"].append(item)
    if attack and control and marker:
        a = read_body(outdir, attack)
        b = read_body(outdir, control)
        result["assert"] = {
            "attack_has_marker": marker.encode() in a,
            "control_has_marker": marker.encode() in b,
            "bodies_differ": hashlib.sha256(a).hexdigest() != hashlib.sha256(b).hexdigest() if a or b else False,
            "attack_excerpt": excerpt_around(a, marker),
            "control_excerpt": excerpt_around(b, marker) if marker.encode() in b else "ABSENT",
        }
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0



WAF_HINTS = (
    "request blocked",
    "access denied",
    "cloudflare",
    "cf-ray",
    "incapsula",
    "sucuri",
    "akamai",
    "captcha",
    "challenge-platform",
    "web application firewall",
    "blocked by",
)


def looks_like_waf(status: Any, body: bytes) -> bool:
    """拦截页不是修复：WAF/挑战页也算「攻击没成功」，但不能据此判 fixed。"""
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    if code in (403, 406, 429, 503):
        return True
    low = body[:4096].lower()
    return any(h.encode() in low for h in WAF_HINTS)


def verify_compare_claims(
    outdir: str,
    comp: dict[str, Any],
    attack_name: str | None,
    control_name: str | None,
    marker: str = "",
) -> tuple[bool, bool, bool, list[str]]:
    """用封印后的 case 证据复算 compare 文件里的断言。

    compare-*.json 本身不参与 HMAC；只有 pack.json 里的 (attack, control, pass)
    被 pack.seal.json 覆盖。因此：
      * pass 只认 pack 里的值（文件里的 pass 只能用来发现篡改）；
      * 文件里的 checks 当声明，逐条用封印后的 body/meta 复算；
      * 无法复算的断言一律按失败处理（fail closed）。

    返回 (verified, has_field_assert, marker_bound, reasons)。
    """
    reasons: list[str] = []
    if not (attack_name and control_name):
        return False, False, False, ["缺少 named attack/control"]
    if comp.get("attack") != attack_name or comp.get("control") != control_name:
        return False, False, False, ["compare 不是本次 named attack/control"]
    f = comp.get("file") or ""
    if not f or not os.path.isfile(f):
        return False, False, False, ["compare 文件缺失或不可读，断言无法复算"]
    try:
        detail = load_json(f)
    except Exception:
        return False, False, False, ["compare 文件无法解析"]
    if not isinstance(detail, dict):
        return False, False, False, ["compare 文件格式错误"]
    if "pass" in detail and bool(detail.get("pass")) != (comp.get("pass") is True):
        return False, False, False, ["compare 文件的 pass 与封印 pack 不一致（文件被改过）"]

    a_meta = load_meta(outdir, attack_name)
    c_meta = load_meta(outdir, control_name)
    a_body = read_body(outdir, attack_name)
    c_body = read_body(outdir, control_name)
    a_status = (a_meta.get("response") or {}).get("status")
    c_status = (c_meta.get("response") or {}).get("status")

    verified_all = True
    has_field = False
    marker_bound = False
    for ch in detail.get("checks") or []:
        if not isinstance(ch, dict):
            verified_all = False
            continue
        name = str(ch.get("name") or "")
        expected = ch.get("expected")
        ok = False
        bound = False
        try:
            if name == "attack_status":
                ok = int(a_status) == int(expected)
            elif name == "control_status":
                ok = int(c_status) == int(expected)
            elif name == "attack_contains":
                exp = str(expected)
                ok = exp.encode("utf-8") in a_body
                bound = bool(marker) and (exp == marker or marker in exp)
            elif name == "control_not_contains":
                exp = str(expected)
                ok = exp.encode("utf-8") not in c_body
                bound = bool(marker) and (exp == marker or marker in exp)
            elif name == "bodies_differ":
                want = expected if isinstance(expected, bool) else str(expected).lower() in ("1", "true", "yes")
                ok = (hashlib.sha256(a_body).hexdigest() != hashlib.sha256(c_body).hexdigest()) == want
            elif name in ("json_path_differs", "attack_json_value"):
                path = ch.get("path") or ""
                if not path:
                    reasons.append("compare 未记录 json path，无法复算")
                else:
                    a_json = json.loads(a_body.decode("utf-8", "replace") or "null")
                    c_json = json.loads(c_body.decode("utf-8", "replace") or "null")
                    cur = a_json
                    for seg in str(path).lstrip("$.").split("."):
                        if isinstance(cur, dict):
                            cur = cur.get(seg)
                        elif isinstance(cur, list) and seg.isdigit():
                            cur = cur[int(seg)]
                        else:
                            cur = None
                            break
                    if name == "json_path_differs":
                        other = c_json
                        for seg in str(path).lstrip("$.").split("."):
                            if isinstance(other, dict):
                                other = other.get(seg)
                            elif isinstance(other, list) and seg.isdigit():
                                other = other[int(seg)]
                            else:
                                other = None
                                break
                        ok = cur != other
                        bound = bool(marker) and marker in json.dumps(cur, ensure_ascii=False)
                    else:
                        ok = str(cur) == str(expected)
                        bound = bool(marker) and marker in str(expected)
            else:
                reasons.append(f"未知断言 {name}，无法复算")
        except Exception as e:  # noqa: BLE001
            reasons.append(f"复算失败 {name}: {e.__class__.__name__}")
        if ok and name in FIELD_CHECK_NAMES:
            has_field = True
            if bound:
                marker_bound = True
        if not ok:
            verified_all = False
    if not (detail.get("checks") or []):
        verified_all = False
    if not verified_all:
        reasons.append("compare 断言无法用封印证据复算（或与证据不符）")
    return bool(verified_all), has_field, marker_bound, reasons


def assess_fixed(
    outdir: str,
    pack: dict[str, Any] | None,
    attack_n: str | None,
    marker: str,
) -> dict[str, Any]:
    """`fixed` 的证据门槛：必须证明「攻击不再成立，而正向对照仍然正常」。

    旧实现只检查 gate.ok != true，于是空包 / 缺 pack / WAF 页 / 超时
    全都能被写成 fixed（审计发现的 fail-open）。这里逐条要求：
      a) 至少一个 attack case，且正文真实落盘、没有网络错误；
      b) attack 确实失败（不含 victim_marker），且不是 WAF 拦截页；
      c) marker 必填，否则无法证明攻击不再返回该字段。
    """
    out: dict[str, Any] = {"ok": False, "reasons": []}
    if not isinstance(pack, dict) or not (pack.get("cases") or []):
        out["reasons"].append("没有 pack.json / 没有任何 case：无法证明已修复（应为 inconclusive）")
        return out
    if not attack_n:
        out["reasons"].append("没有 attack case：无法证明攻击已失败（应为 inconclusive）")
        return out
    a_dir = os.path.join(outdir, "cases", attack_n)
    a_meta = load_meta(outdir, attack_n)
    a_resp = a_meta.get("response") or {}
    a_status = a_resp.get("status")
    a_err = a_resp.get("error")
    a_body = read_body(outdir, attack_n)
    a_path = os.path.join(a_dir, "response.body")

    ok_seal, why_seal = verify_case(a_dir)
    if not ok_seal:
        out["reasons"].append(f"attack 证据未封印（{why_seal}）：不能据此声称已修复")
    if not os.path.isfile(a_path) or not a_body:
        out["reasons"].append("attack 没有 response.body：抓取失败不能当成「已修复」（应为 inconclusive）")
    if a_err:
        out["reasons"].append(f"attack 抓取出错（{a_err}）：超时/连接失败不能当成「已修复」（应为 inconclusive）")
    if looks_like_waf(a_status, a_body):
        out["reasons"].append(f"attack 命中 WAF/拦截页（status={a_status}）：拦截不是修复（应为 inconclusive）")
    if marker:
        if marker.encode("utf-8") in a_body:
            out["reasons"].append("attack 正文里仍有 victim_marker：攻击仍然成立，不能写 fixed")
    else:
        out["reasons"].append("fixed 必须带 victim_marker，才能证明攻击不再返回该字段")
    out["ok"] = not out["reasons"]
    return out

def cmd_gate(args: argparse.Namespace) -> int:
    if empty(args.outdir):
        print("ERROR: outdir 必填", file=sys.stderr)
        return 2
    live = evaluate(args.outdir, args.kind, args.victim_marker, args.attack, args.control)
    merged = write_signed_gate(os.path.abspath(args.outdir), live)
    print(json.dumps(merged, ensure_ascii=False, indent=2, default=str))
    return 0 if live.get("ok") else 1


def _live_from_args(args: argparse.Namespace, require_marker: bool) -> dict[str, Any] | None:
    if empty(args.outdir):
        return None
    marker = getattr(args, "victim_marker", "") or ""
    if require_marker and empty(marker):
        return None
    return evaluate(args.outdir, getattr(args, "kind", "") or "", marker, getattr(args, "attack", "") or "", getattr(args, "control", "") or "")


def cmd_verdict(args: argparse.Namespace) -> int:
    if empty(args.outdir) or empty(args.verdict):
        print("ERROR: outdir, verdict 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    verdict = args.verdict.strip().lower()
    advice = (args.submit_advice or "").strip().lower()
    summary = args.summary or ""
    allowed = {"reproduced", "not_a_vuln", "fixed", "inconclusive"}
    if verdict not in allowed:
        print(json.dumps({"ok": False, "error": f"verdict 必须是 {sorted(allowed)}"}))
        return 2

    errors: list[str] = []
    live = None
    marker = (getattr(args, "victim_marker", "") or "").strip()
    # 先读「已存在的签名 gate」，后面所有比对都用它。
    # 旧实现先 write_signed_gate 再比对 signoff.challenge，等于每次 verdict 都把
    # 用户签过的那份 gate 换成新 challenge，于是 ready 永远不可能通过，
    # 而且一条被拒的 verdict 还会顺手毁掉原本有效的 gate。
    persisted_gate = load_signed_gate(outdir)
    # 所有结论都现场重算。reproduced 必须 ok；fixed 不允许闸门仍判定可复现。
    live = evaluate(
        outdir,
        getattr(args, "kind", "") or "",
        marker,
        getattr(args, "attack", "") or "",
        getattr(args, "control", "") or "",
    )
    if verdict == "reproduced":
        if empty(marker):
            errors.append("reproduced 必须带 victim_marker，并现场重算闸门（不信任磁盘 gate.json）")
        elif not live.get("ok"):
            errors.append("reproduced 被拒绝：现场闸门 ok=false（手改 gate.json 无效）")
            errors.extend(live.get("reasons") or [])
    elif verdict == "fixed":
        if live.get("ok"):
            errors.append("fixed 被拒绝：现场闸门仍然 ok=true，当前证据仍能复现，不能写成已修复")
        try:
            pack_for_fixed = load_pack(outdir)
        except FileNotFoundError:
            pack_for_fixed = None
        fixed = assess_fixed(
            outdir, pack_for_fixed, getattr(args, "attack", "") or None, marker
        )
        if not fixed.get("ok"):
            errors.append("fixed 被拒绝：证据不足以证明已修复（应为 inconclusive）")
            errors.extend(fixed.get("reasons") or [])
        if advice == "ready":
            errors.append("fixed 不能 ready：只有 reproduced 才能进入签字提交流程")

    signoff_path = os.path.join(outdir, "signoff.json")
    signoff_raw = load_json(signoff_path) if os.path.isfile(signoff_path) else None
    signed_off, signoff_why = verify_document(signoff_raw)
    signoff_fp = None
    signoff_challenge = None
    if signed_off and isinstance(signoff_raw, dict):
        pl = signoff_raw.get("payload") or {}
        signoff_fp = pl.get("fingerprint")
        signoff_challenge = pl.get("challenge")

    lab = True
    fp = None
    try:
        pack = load_pack(outdir)
        lab = is_lab_sealed(outdir, pack)
        fp = pack_fingerprint(outdir)
    except FileNotFoundError:
        errors.append("missing pack.json")

    if live is not None:
        lab = bool(live.get("lab"))
        fp = live.get("fingerprint") or fp

    if advice == "ready":
        if lab:
            errors.append("靶场禁止 ready")
        if verdict != "reproduced":
            errors.append("ready 仅允许 reproduced")
        if not signed_off:
            errors.append(f"ready 被拒绝：signoff.json 缺 HMAC 或伪造（{signoff_why}）。必须 retest_signoff")
        if live is None or not live.get("ok"):
            errors.append("ready 被拒绝：现场闸门未通过")
        if signed_off and fp and signoff_fp != fp:
            errors.append("signoff 指纹与当前证据包不一致")
        if signed_off and not persisted_gate:
            errors.append("ready 被拒绝：没有 HMAC 签名的 gate.json（先跑 retest_strict_gate）")
        elif signed_off and signoff_challenge != persisted_gate.get("challenge"):
            errors.append("signoff challenge 与签名 gate.json 不一致")
        elif signed_off and live.get("challenge") and persisted_gate.get("challenge") != live.get("challenge"):
            errors.append("gate.json 的 challenge 已过期（gate 之后证据变了），重跑 gate 再签字")

    if lab:
        advice = "never"
    if verdict == "not_a_vuln":
        advice = "never"
    if not advice:
        advice = "never" if (lab or verdict != "reproduced") else "needs-human"
    if advice not in ("never", "needs-human", "ready"):
        errors.append("submit_advice 必须是 never|needs-human|ready")

    if errors:
        out_payload = {
            "ok": False,
            "rejected": True,
            "verdict": verdict,
            "submit_advice": "never",
            "errors": errors,
            "live_ok": bool(live and live.get("ok")),
            "fingerprint": fp,
        }
        doc = sign_document("verdict", out_payload)
        dump_json(os.path.join(outdir, "verdict.json"), doc)
        audit("verdict_rejected", outdir=outdir, errors=errors, verdict=verdict)
        print(json.dumps({**out_payload, "hmac_sha256": doc["hmac_sha256"]}, ensure_ascii=False, indent=2, default=str))
        return 1

    # 只有被接受的 verdict 才刷新 gate.json，且仅在缺失/过期时才写——否则一条结论
    # 会顺手把用户刚签过的那份 gate 覆盖掉。
    if (
        not persisted_gate
        or persisted_gate.get("fingerprint") != live.get("fingerprint")
        or persisted_gate.get("challenge") != live.get("challenge")
    ):
        write_signed_gate(outdir, live)

    out_payload = {
        "ok": True,
        "rejected": False,
        "verdict": verdict,
        "submit_advice": advice,
        "summary": summary,
        "fingerprint": fp,
        "lab": lab,
        "gate_ok": bool(live and live.get("ok")) if live is not None else False,
        "signed_off": signed_off,
        "live": True,
        "pack": os.path.join(outdir, "pack.json"),
        "ts": now(),
    }
    doc = sign_document("verdict", out_payload)
    dump_json(os.path.join(outdir, "verdict.json"), doc)
    audit("verdict", outdir=outdir, verdict=verdict, advice=advice, fingerprint=fp)
    print(json.dumps({**out_payload, "hmac_sha256": doc["hmac_sha256"]}, ensure_ascii=False, indent=2, default=str))
    return 0


def load_signed_gate(outdir: str) -> dict[str, Any] | None:
    path = os.path.join(outdir, "gate.json")
    if not os.path.isfile(path):
        return None
    raw = load_json(path)
    ok, _ = verify_document(raw)
    if not ok or not isinstance(raw.get("payload"), dict):
        return None
    return raw["payload"]


def load_signed_gate_challenge(outdir: str) -> str | None:
    g = load_signed_gate(outdir)
    return (g or {}).get("challenge")


def cmd_signoff(args: argparse.Namespace) -> int:
    if empty(args.outdir) or empty(args.phrase):
        print("ERROR: outdir, phrase 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    phrase = (args.phrase or "").strip()
    gate = load_signed_gate(outdir)
    if not gate:
        print(json.dumps({"ok": False, "error": "没有 HMAC 签名的 gate.json。先跑 retest_strict_gate；手写 gate.json 无效"}))
        return 1
    challenge = str(gate.get("challenge") or "")
    if not challenge:
        print(json.dumps({"ok": False, "error": "gate.json 无 challenge"}))
        return 1
    accepted = False
    for base in SIGNOFF_PHRASES:
        if phrase == f"{base} {challenge}":
            accepted = True
            break
    if not accepted:
        out = {
            "ok": False,
            "error": "口令必须是用户亲口整句，且末尾带本次 gate.challenge（12 位十六进制）。"
            + "格式：I inspected the evidence pack and approve submit <challenge> "
            + "或 我已核验证据包并批准提交 <challenge>。"
            + f" Agent 不得代填。当前 challenge 只存在于签名 gate.json。",
        }
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 1
    if not gate.get("ok"):
        print(json.dumps({"ok": False, "error": "gate.ok=false，不能签字提交"}))
        return 1
    try:
        pack = load_pack(outdir)
    except FileNotFoundError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    if is_lab_sealed(outdir, pack) or gate.get("lab"):
        print(json.dumps({"ok": False, "error": "靶场禁止签字提交三家"}))
        return 1
    fp = pack_fingerprint(outdir)
    if gate.get("fingerprint") != fp:
        print(json.dumps({"ok": False, "error": "gate 指纹过期（gate 之后文件变了），重跑 gate"}))
        return 1
    # live re-eval with same marker
    live = evaluate(outdir, gate.get("kind") or "", gate.get("victim_marker") or "", gate.get("attack") or "", gate.get("control") or "")
    if not live.get("ok"):
        print(json.dumps({"ok": False, "error": "现场闸门已不再通过，不能签字", "reasons": live.get("reasons")}))
        return 1
    if live.get("fingerprint") != fp:
        print(json.dumps({"ok": False, "error": "现场指纹不一致"}))
        return 1
    payload = {
        "ok": True,
        "phrase_ok": True,
        "fingerprint": fp,
        "challenge": challenge,
        "note": args.note or "",
        "warning": "只证明用户看过证据包指纹并批准；仍须用户在 H1/Bugcrowd/Intigriti 网页上点提交。",
    }
    doc = sign_document("signoff", payload)
    dump_json(os.path.join(outdir, "signoff.json"), doc)
    audit("signoff", outdir=outdir, fingerprint=fp, challenge=challenge)
    print(json.dumps({**payload, "hmac_sha256": doc["hmac_sha256"]}, ensure_ascii=False, indent=2))
    return 0


def build() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="retest_strict")
    sub = p.add_subparsers(dest="cmd", required=True)

    prev = sub.add_parser("preview")
    prev.add_argument("--outdir", default="")
    prev.add_argument("--victim-marker", default="")
    prev.add_argument("--attack", default="")
    prev.add_argument("--control", default="")

    g = sub.add_parser("gate")
    g.add_argument("--outdir", default="")
    g.add_argument("--kind", default="")
    g.add_argument("--victim-marker", default="")
    g.add_argument("--attack", default="")
    g.add_argument("--control", default="")

    v = sub.add_parser("verdict")
    v.add_argument("--outdir", default="")
    v.add_argument("--verdict", default="")
    v.add_argument("--submit-advice", default="")
    v.add_argument("--summary", default="")
    v.add_argument("--victim-marker", default="")
    v.add_argument("--kind", default="")
    v.add_argument("--attack", default="")
    v.add_argument("--control", default="")

    s = sub.add_parser("signoff")
    s.add_argument("--outdir", default="")
    s.add_argument("--phrase", default="")
    s.add_argument("--note", default="")
    return p


def main() -> int:
    args = build().parse_args()
    if args.cmd == "preview":
        return cmd_preview(args)
    if args.cmd == "gate":
        return cmd_gate(args)
    if args.cmd == "verdict":
        return cmd_verdict(args)
    if args.cmd == "signoff":
        return cmd_signoff(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
