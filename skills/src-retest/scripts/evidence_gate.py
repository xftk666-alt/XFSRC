#!/usr/bin/env python3
"""检查证据包是否达到提交/reproduced 门槛。不信任 Markdown 口述。"""
from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlparse

LAB_HINTS = (
    "172.18.0.",
    "juice-shop",
    "juice-sh.op",
    "localhost",
    "127.0.0.1",
    "hackthebox",
    "portswigger",
    "tryhackme",
)


def load(outdir: str) -> dict:
    p = os.path.join(outdir, "pack.json")
    if not os.path.isfile(p):
        raise FileNotFoundError(p)
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def hosts(pack: dict) -> list[str]:
    hs = []
    for c in pack.get("cases") or []:
        u = c.get("url") or ""
        try:
            hs.append((urlparse(u).hostname or "").lower())
        except Exception:
            pass
    return hs


def _body(outdir: str, name: str) -> bytes:
    path = os.path.join(outdir, "cases", name, "response.body")
    if not os.path.isfile(path):
        return b""
    with open(path, "rb") as fh:
        return fh.read()


def _compare_claims_hold(outdir: str, comp: dict) -> bool:
    """用封印后的 body 复算 compare 的字段级断言。任一断言不成立即不通过。"""
    f = comp.get("file") or ""
    if not f or not os.path.isfile(f):
        return False
    try:
        with open(f, encoding="utf-8") as fh:
            detail = json.load(fh)
    except Exception:
        return False
    if not isinstance(detail, dict):
        return False
    attack = comp.get("attack") or ""
    control = comp.get("control") or ""
    if not attack or not control:
        return False
    a_body = _body(outdir, attack)
    c_body = _body(outdir, control)
    if not a_body:
        return False
    field_names = {"attack_contains", "control_not_contains", "json_path_differs", "attack_json_value"}
    seen_field = False
    for ch in detail.get("checks") or []:
        if not isinstance(ch, dict):
            return False
        name = str(ch.get("name") or "")
        expected = ch.get("expected")
        if name == "attack_contains":
            seen_field = True
            if str(expected).encode("utf-8") not in a_body:
                return False
        elif name == "control_not_contains":
            seen_field = True
            if str(expected).encode("utf-8") in c_body:
                return False
        elif name in ("json_path_differs", "attack_json_value"):
            seen_field = True
            path = ch.get("path") or ""
            if not path:
                return False
            try:
                a_json = json.loads(a_body.decode("utf-8", "replace") or "null")
                c_json = json.loads(c_body.decode("utf-8", "replace") or "null")
            except Exception:
                return False
            segs = str(path).lstrip("$.").split(".")

            def walk(doc):
                cur = doc
                for seg in segs:
                    if isinstance(cur, dict):
                        cur = cur.get(seg)
                    elif isinstance(cur, list) and seg.isdigit():
                        cur = cur[int(seg)]
                    else:
                        return None
                return cur

            av, cv = walk(a_json), walk(c_json)
            if name == "json_path_differs" and av == cv:
                return False
            if name == "attack_json_value" and str(av) != str(expected):
                return False
        elif name in field_names:
            seen_field = True
        # 其它断言（状态码等）不构成字段级证据，忽略。
    return seen_field


def main() -> int:
    outdir = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
    kind = (sys.argv[2] if len(sys.argv) > 2 else "").strip().lower()
    if not outdir or outdir.startswith("{") or outdir in ("none", "null", "-"):
        print("ERROR: outdir required", file=sys.stderr)
        return 2
    outdir = os.path.abspath(outdir)
    try:
        pack = load(outdir)
    except FileNotFoundError as e:
        print(json.dumps({"ok": False, "reason": f"missing pack.json: {e}", "submit_advice": "never"}))
        return 1

    cases = pack.get("cases") or []
    compares = pack.get("compares") or []
    reasons: list[str] = []
    ok = True

    if not cases:
        ok = False
        reasons.append("no cases recorded")

    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, "/usr/local/share/artex-src")
        from evidence_seal import verify_pack, verify_pack_cases

        # pack.seal.json 覆盖 case 归属 / compares.pass / 截图哈希；少了这一步，
        # 手改 pack.json 把 compares.pass 改成 true 就能过闸（审计发现）。
        pack_ok, pack_why = verify_pack(outdir)
        if not pack_ok:
            ok = False
            reasons.append(f"pack.seal.json 校验未通过（{pack_why}）")
        integ = verify_pack_cases(outdir)
        if not integ.get("ok"):
            ok = False
            reasons.append("unsigned or tampered cases (seal.json hmac)")
    except Exception as e:
        ok = False
        reasons.append(f"integrity check failed: {e}")

    # 靶场判定：统一走 lab_detect（网段/后缀/单标签规则），旧子串保留兜底
    lab = False
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from lab_detect import is_lab as _detect_lab

        lab = bool(_detect_lab(pack))
    except Exception:
        lab = False
    blob = json.dumps(pack)
    if not lab:
        lab = any(h in blob for h in LAB_HINTS)

    passed_compare = [c for c in compares if c.get("pass") is True]
    failed_compare = [c for c in compares if c.get("pass") is False]

    xss_cases = [c for c in cases if c.get("kind") == "browser-xss" or c.get("dialog_executed") is not None]
    if kind == "xss" or xss_cases:
        executed = any(c.get("dialog_executed") for c in xss_cases)
        if not executed:
            ok = False
            reasons.append("XSS requires dialog_executed=true (browser_xss_evidence)")
        for c in xss_cases:
            shot = os.path.join(c.get("dir") or "", "screenshot.png")
            if c.get("dialog_executed") and not os.path.isfile(shot):
                ok = False
                reasons.append("XSS screenshot.png missing")
    else:
        if not passed_compare:
            ok = False
            reasons.append("need at least one http_evidence_compare with pass=true")
        # 字段级断言必须用封印后的 case 现场复算：compare-*.json 不参与 HMAC，
        # 直接信它的 checks 等于允许手写一份「字段对照」过闸。
        field_ok = False
        for c in passed_compare:
            if _compare_claims_hold(outdir, c):
                field_ok = True
        if passed_compare and not field_ok:
            ok = False
            reasons.append("status-only compare ignored: need attack_contains or json_path (victim/secret field)")
        names = [(c.get("name") or "") for c in cases]
        if not any(n.startswith("attack") for n in names):
            ok = False
            reasons.append("need an attack-* case")
        if not any(n.startswith("control") for n in names):
            ok = False
            reasons.append("need a control-* case")

    # SPA false-positive: attack body sha == homepage
    # 注意：只认「名字叫 home/index」或「URL 路径就是根 /」的 case。
    # 原来用 url.endswith("/") 判断，把 /ftp/、/admin/ 这类任何带尾斜杠的路径
    # 全当成首页，导致真实差异被误判成「attack 等于首页」而拒收（实测踩过）。
    home_shas = set()
    for c in cases:
        url = c.get("url") or ""
        name = (c.get("name") or "").lower()
        try:
            path = urlparse(url).path or "/"
        except Exception:
            path = "/"
        is_root = path in ("", "/")
        if name in ("control-home", "home", "index") or is_root:
            if c.get("body_sha256"):
                home_shas.add(c.get("body_sha256"))
    for c in cases:
        n = (c.get("name") or "")
        if n.startswith("attack") and c.get("body_sha256") in home_shas:
            ok = False
            reasons.append(f"SPA fallback: {n} sha256 equals homepage")
    for c in failed_compare:
        if "fake" in (c.get("attack") or "") or "git" in (c.get("attack") or "") or "env" in (c.get("attack") or ""):
            reasons.append(f"control matched homepage (likely SPA fallback): {c.get('file')}")

    if lab:
        submit = "never"
        reasons.append("lab/CTF/Juice Shop host → never submit to H1/Bugcrowd/Intigriti")
    elif not ok:
        submit = "never"
    else:
        submit = "needs-human"  # never auto-ready; need retest_signoff

    result = {
        "ok": ok,
        "verdict_allowed": ("reproduced" if ok else ("not_a_vuln" if any("SPA fallback" in r or "status-only" in r for r in reasons) else "inconclusive")),
        "submit_advice": submit,
        "n_cases": len(cases),
        "n_compares_pass": len(passed_compare),
        "n_compares_fail": len(failed_compare),
        "reasons": reasons,
        "pack": os.path.join(outdir, "pack.json"),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
