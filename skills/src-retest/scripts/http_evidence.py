#!/usr/bin/env python3
"""独立 HTTP 证据记录 / 对照实验。

不信任模型口述。每次请求把原始请求、响应头、响应体、sha256 落到磁盘，
并可用 attack vs control 做硬对照（状态码、正文、JSON 字段）。

RFC1918 / juice-shop / localhost 自动绕过全局代理。
默认不跟随重定向（避免 SSRF 验证时客户端自己去拉 imageUrl）。

子命令:
  record   发一次请求并写入 outdir/cases/<name>/
  compare  对照两个已记录 case，写出 compare-<attack>-vs-<control>.json
  summary  打印 pack.json 摘要
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
if "/usr/local/share/artex-src" not in sys.path:
    sys.path.append("/usr/local/share/artex-src")
try:
    from evidence_seal import (
        seal_case as _seal_case,
        seal_pack as _seal_pack,
        recorder_token as _recorder_token,
        RECORDER_TOKEN_ENV as _RECORDER_TOKEN_ENV,
    )
except Exception:
    _seal_case = None  # type: ignore
    _seal_pack = None  # type: ignore
    _recorder_token = None  # type: ignore
    _RECORDER_TOKEN_ENV = "ARTEX_EVIDENCE_RECORDER_TOKEN"

RECORDER_ID = "artex-recorder/2"


PLACEHOLDER = re.compile(r"^\{[a-zA-Z0-9_]+\}$")
CTX = ssl._create_unverified_context()
MAX_BODY_SAVE = 2 * 1024 * 1024
EXCERPT = 4096


def empty(v: str | None) -> bool:
    if v is None:
        return True
    v = str(v).strip()
    return (not v) or bool(PLACEHOLDER.match(v)) or v.lower() in ("none", "null", "-")


def host_of(url: str) -> str:
    p = urlparse(url)
    h = p.hostname or ""
    return h.lower()


def is_priv(host: str) -> bool:
    h = (host or "").lower()
    if h in ("juice-shop", "localhost", "host.docker.internal") or h.endswith(".local"):
        return True
    if h.endswith(".juice-sh.op") or h == "juice-sh.op":
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def unset_proxy_if_priv(url: str) -> None:
    if is_priv(host_of(url)):
        for k in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ):
            os.environ.pop(k, None)
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"


def jget(obj: Any, path: str) -> Any:
    cur = obj
    path = path.replace("[", ".").replace("]", "")
    for p in path.split("."):
        if p == "":
            continue
        if isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)]
        elif isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def parse_headers(header: str, cookie: str, bearer: str) -> dict[str, str]:
    h: dict[str, str] = {"Accept": "*/*", "User-Agent": "artex-http-evidence/1.0"}
    if not empty(header):
        for line in header.replace("\r", "").split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            h[k.strip()] = v.strip()
    if not empty(cookie):
        h["Cookie"] = cookie
    if not empty(bearer):
        h["Authorization"] = "Bearer " + bearer.strip()
    return h


def redact(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in ("authorization", "cookie", "proxy-authorization"):
            out[k] = (v[:12] + "…redacted") if len(v) > 12 else "redacted"
        else:
            out[k] = v
    return out


def load_pack(outdir: str) -> dict[str, Any]:
    path = os.path.join(outdir, "pack.json")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"created_at": datetime.now(timezone.utc).isoformat(), "cases": []}


def save_pack(outdir: str, pack: dict[str, Any]) -> None:
    os.makedirs(outdir, exist_ok=True)
    pack["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(os.path.join(outdir, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f, ensure_ascii=False, indent=2)
        f.write("\n")


def cmd_record(args: argparse.Namespace) -> int:
    if empty(args.outdir) or empty(args.name) or empty(args.url):
        print("ERROR: outdir, name, url 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", args.name.strip())
    url = args.url.strip()
    method = (args.method or "GET").strip().upper()
    if empty(method) or PLACEHOLDER.match(method):
        method = "GET"
    max_redirs = 0
    if not empty(args.max_redirs):
        try:
            max_redirs = int(args.max_redirs)
        except ValueError:
            max_redirs = 0
    timeout = 15.0
    if not empty(args.timeout):
        try:
            timeout = float(args.timeout)
        except ValueError:
            timeout = 15.0

    unset_proxy_if_priv(url)
    headers = parse_headers(args.header, args.cookie, args.bearer)
    body_bytes = None
    if not empty(args.body):
        body_bytes = args.body.encode("utf-8")
        if empty(args.content_type):
            headers.setdefault("Content-Type", "application/json")
        else:
            headers["Content-Type"] = args.content_type
    elif not empty(args.content_type):
        headers["Content-Type"] = args.content_type

    class PassThroughHTTPErrorProcessor(urllib.request.HTTPErrorProcessor):
        def http_response(self, request, response):  # type: ignore[no-untyped-def]
            return response

        https_response = http_response

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
            return None

    handlers: list[Any] = [
        urllib.request.HTTPSHandler(context=CTX),
        PassThroughHTTPErrorProcessor,
    ]
    if max_redirs <= 0:
        handlers.append(NoRedirectHandler)
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    t0 = time.time()
    status = 0
    resp_headers: list[tuple[str, str]] = []
    raw = b""
    err = None
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            resp_headers = list(resp.headers.items())
            raw = resp.read(MAX_BODY_SAVE + 1)
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = list(e.headers.items()) if e.headers else []
        try:
            raw = e.read(MAX_BODY_SAVE + 1)
        except Exception:
            raw = b""
    except Exception as e:
        err = f"{type(e).__name__}: {e}"

    elapsed_ms = int((time.time() - t0) * 1000)
    truncated = len(raw) > MAX_BODY_SAVE
    if truncated:
        raw = raw[:MAX_BODY_SAVE]
    sha = hashlib.sha256(raw).hexdigest() if not err else None
    excerpt = raw[:EXCERPT]
    ctype = ""
    for k, v in resp_headers:
        if k.lower() == "content-type":
            ctype = v
            break

    case_dir = os.path.join(outdir, "cases", name)
    os.makedirs(case_dir, exist_ok=True)

    req_txt = [
        f"{method} {url}",
        f"Host: {host_of(url)}",
    ]
    for k, v in headers.items():
        req_txt.append(f"{k}: {v}")
    req_txt.append("")
    if body_bytes:
        req_txt.append(body_bytes.decode("utf-8", "replace"))
    with open(os.path.join(case_dir, "request.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(req_txt) + "\n")

    hdr_lines = [f"HTTP {status}"] + [f"{k}: {v}" for k, v in resp_headers]
    if err:
        hdr_lines.append(f"ERROR: {err}")
    with open(os.path.join(case_dir, "response_headers.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(hdr_lines) + "\n")

    with open(os.path.join(case_dir, "response.body"), "wb") as f:
        f.write(raw)

    parsed = None
    if raw and "json" in (ctype or "").lower():
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            parsed = None
    if parsed is None and raw[:1] in (b"{", b"["):
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            parsed = None

    checks: list[dict[str, Any]] = []

    def add_check(n: str, ok: bool, expected: Any, actual: Any) -> None:
        checks.append({"name": n, "pass": bool(ok), "expected": expected, "actual": actual})

    if not empty(args.expect_status):
        try:
            exp = int(args.expect_status)
            add_check("status", status == exp, exp, status)
        except ValueError:
            add_check("status", False, args.expect_status, status)
    if not empty(args.expect_contains):
        needle = args.expect_contains.encode("utf-8")
        add_check("contains", needle in raw, args.expect_contains, excerpt.decode("utf-8", "replace")[:500])
    if not empty(args.expect_not_contains):
        needle = args.expect_not_contains.encode("utf-8")
        add_check("not_contains", needle not in raw, args.expect_not_contains, "absent" if needle not in raw else "present")
    if not empty(args.expect_content_type):
        add_check(
            "content_type",
            args.expect_content_type.lower() in ctype.lower(),
            args.expect_content_type,
            ctype,
        )
    json_actual = None
    if not empty(args.expect_json_path):
        json_actual = jget(parsed, args.expect_json_path) if parsed is not None else None
        if empty(args.expect_json_value):
            add_check("json_path_present", json_actual is not None, args.expect_json_path, json_actual)
        else:
            expv = args.expect_json_value
            add_check("json_path", str(json_actual) == str(expv), expv, json_actual)

    all_pass = all(c["pass"] for c in checks) if checks else None
    auth_raw = headers.get("Authorization") or ""
    if not auth_raw and headers.get("Cookie"):
        m = re.search(r"(?i)(?:^|;\s*)token=([^;]+)", headers.get("Cookie") or "")
        auth_raw = (m.group(1) if m else "") or ""
    auth_sha = hashlib.sha256(auth_raw.encode("utf-8")).hexdigest() if auth_raw else None
    meta = {
        "name": name,
        "ts": datetime.now(timezone.utc).isoformat(),
        "recorder": RECORDER_ID,
        "recorder_seq": f"{int(t0 * 1000)}-{os.getpid()}-{hashlib.sha256(os.urandom(16)).hexdigest()[:12]}",
        "elapsed_ms": elapsed_ms,
        "request": {
            "method": method,
            "url": url,
            "headers_redacted": redact(headers),
            "body_len": len(body_bytes or b""),
            "max_redirs": max_redirs,
            "auth_sha256": auth_sha,
        },
        "response": {
            "status": status,
            "content_type": ctype,
            "body_len": len(raw),
            "body_sha256": sha,
            "truncated": truncated,
            "error": err,
        },
        "json_path_value": json_actual,
        "checks": checks,
        "checks_pass": all_pass,
        "files": {
            "request": os.path.join(case_dir, "request.txt"),
            "response_headers": os.path.join(case_dir, "response_headers.txt"),
            "response_body": os.path.join(case_dir, "response.body"),
        },
    }
    with open(os.path.join(case_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2, default=str)
        f.write("\n")

    pack = load_pack(outdir)
    pack["cases"] = [c for c in pack.get("cases", []) if c.get("name") != name]
    pack["cases"].append(
        {
            "name": name,
            "status": status,
            "url": url,
            "method": method,
            "body_sha256": sha,
            "body_len": len(raw),
            "content_type": ctype,
            "checks_pass": all_pass,
            "dir": case_dir,
        }
    )
    save_pack(outdir, pack)
    # 封印失败必须是非零退出：旧实现只打一行 warning 就返回 0，agent 会以为证据
    # 已经落盘并封印，直到后面跑闸门才发现（那时已经浪费了一整轮复测）。
    seal_errors: list[str] = []
    if _seal_case is None or _seal_pack is None:
        seal_errors.append("evidence_seal 模块不可用：证据无法封印")
    else:
        tok = _recorder_token() if _recorder_token else ""
        if not tok:
            seal_errors.append("缺少记录器令牌文件：证据无法封印")
        else:
            os.environ[_RECORDER_TOKEN_ENV] = tok
        if not seal_errors:
            try:
                _seal_case(case_dir)
            except Exception as e:  # noqa: BLE001
                seal_errors.append(f"case seal failed: {e.__class__.__name__}: {e}")
            try:
                _seal_pack(outdir)
            except Exception as e:  # noqa: BLE001
                seal_errors.append(f"pack seal failed: {e.__class__.__name__}: {e}")
    for msg in seal_errors:
        print(json.dumps({"error": msg}), file=sys.stderr)

    out = dict(meta)
    if seal_errors:
        out["ok"] = False
        out["seal_errors"] = seal_errors
    out["body_excerpt"] = excerpt.decode("utf-8", "replace")
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    if seal_errors:
        return 3
    if checks and not all_pass:
        return 1
    if err and not checks:
        return 1
    return 0


def load_case(outdir: str, name: str) -> dict[str, Any]:
    path = os.path.join(outdir, "cases", name, "meta.json")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"case not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_compare(args: argparse.Namespace) -> int:
    if empty(args.outdir) or empty(args.attack) or empty(args.control):
        print("ERROR: outdir, attack, control 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    attack = load_case(outdir, args.attack)
    control = load_case(outdir, args.control)
    checks: list[dict[str, Any]] = []

    def add(n: str, ok: bool, expected: Any, actual: Any) -> None:
        checks.append({"name": n, "pass": bool(ok), "expected": expected, "actual": actual})

    ast = attack.get("response", {}).get("status")
    cst = control.get("response", {}).get("status")
    if not empty(args.attack_status):
        add("attack_status", ast == int(args.attack_status), int(args.attack_status), ast)
    if not empty(args.control_status):
        add("control_status", cst == int(args.control_status), int(args.control_status), cst)

    a_body = b""
    c_body = b""
    ap = os.path.join(outdir, "cases", args.attack, "response.body")
    cp = os.path.join(outdir, "cases", args.control, "response.body")
    if os.path.isfile(ap):
        a_body = open(ap, "rb").read()
    if os.path.isfile(cp):
        c_body = open(cp, "rb").read()

    if not empty(args.attack_contains):
        add("attack_contains", args.attack_contains.encode() in a_body, args.attack_contains, True)
    if not empty(args.control_not_contains):
        add(
            "control_not_contains",
            args.control_not_contains.encode() not in c_body,
            args.control_not_contains,
            args.control_not_contains.encode() not in c_body,
        )
    if not empty(args.bodies_differ):
        want = str(args.bodies_differ).lower() in ("1", "true", "yes", "y")
        a_sha_live = hashlib.sha256(a_body).hexdigest() if a_body is not None else attack.get("response", {}).get("body_sha256")
        c_sha_live = hashlib.sha256(c_body).hexdigest() if c_body is not None else control.get("response", {}).get("body_sha256")
        differ = a_sha_live != c_sha_live
        add("bodies_differ", differ == want, want, differ)

    if not empty(args.json_path):
        def parse_maybe(raw: bytes) -> Any:
            try:
                return json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                return None

        av = jget(parse_maybe(a_body), args.json_path)
        cv = jget(parse_maybe(c_body), args.json_path)
        add("json_path_differs", av != cv, f"{args.json_path} differ", {"attack": av, "control": cv})
        if not empty(args.attack_json_value):
            add("attack_json_value", str(av) == str(args.attack_json_value), args.attack_json_value, av)

    all_pass = all(c["pass"] for c in checks) if checks else False
    result = {
        "attack": args.attack,
        "control": args.control,
        "attack_status": ast,
        "control_status": cst,
        "attack_sha256": attack.get("response", {}).get("body_sha256"),
        "control_sha256": control.get("response", {}).get("body_sha256"),
        "checks": checks,
        "pass": all_pass,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(outdir, exist_ok=True)
    outp = os.path.join(outdir, f"compare-{args.attack}-vs-{args.control}.json")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    result["file"] = outp
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    pack = load_pack(outdir)
    comps = pack.get("compares") or []
    comps = [c for c in comps if not (c.get("attack") == args.attack and c.get("control") == args.control)]
    comps.append({"attack": args.attack, "control": args.control, "pass": all_pass, "file": outp})
    pack["compares"] = comps
    save_pack(outdir, pack)
    if _seal_pack is not None:
        try:
            tok = _recorder_token() if _recorder_token else ""
            if tok:
                os.environ[_RECORDER_TOKEN_ENV] = tok
            _seal_pack(outdir)
        except Exception as e:
            print(json.dumps({"warning": f"pack seal failed: {e}"}), file=sys.stderr)
    return 0 if all_pass else 1


def cmd_summary(args: argparse.Namespace) -> int:
    if empty(args.outdir):
        print("ERROR: outdir 必填", file=sys.stderr)
        return 2
    outdir = os.path.abspath(args.outdir)
    pack = load_pack(outdir)
    print(json.dumps(pack, ensure_ascii=False, indent=2))
    return 0


def build() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="http_evidence")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record")
    r.add_argument("--outdir", default="")
    r.add_argument("--name", default="")
    r.add_argument("--method", default="GET")
    r.add_argument("--url", default="")
    r.add_argument("--header", default="")
    r.add_argument("--cookie", default="")
    r.add_argument("--bearer", default="")
    r.add_argument("--body", default="")
    r.add_argument("--content-type", default="")
    r.add_argument("--max-redirs", default="0")
    r.add_argument("--timeout", default="15")
    r.add_argument("--expect-status", default="")
    r.add_argument("--expect-contains", default="")
    r.add_argument("--expect-not-contains", default="")
    r.add_argument("--expect-content-type", default="")
    r.add_argument("--expect-json-path", default="")
    r.add_argument("--expect-json-value", default="")

    c = sub.add_parser("compare")
    c.add_argument("--outdir", default="")
    c.add_argument("--attack", default="")
    c.add_argument("--control", default="")
    c.add_argument("--attack-status", default="")
    c.add_argument("--control-status", default="")
    c.add_argument("--attack-contains", default="")
    c.add_argument("--control-not-contains", default="")
    c.add_argument("--bodies-differ", default="true")
    c.add_argument("--json-path", default="")
    c.add_argument("--attack-json-value", default="")

    s = sub.add_parser("summary")
    s.add_argument("--outdir", default="")
    return p


def main() -> int:
    p = build()
    args = p.parse_args()
    if args.cmd == "record":
        return cmd_record(args)
    if args.cmd == "compare":
        return cmd_compare(args)
    if args.cmd == "summary":
        return cmd_summary(args)
    p.error("unknown cmd")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
