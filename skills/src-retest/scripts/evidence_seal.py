#!/usr/bin/env python3
"""证据包 HMAC 封印：防止手写/篡改 response.body 冒充 http_evidence_record。

只由 record / browser_xss_evidence 在落盘后调用。
有 bash 且能读密钥的 Agent 仍可重签——这是同容器的上限；本封印挡住 Write 工具直接改 body。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

# 密钥与记录器令牌都只从固定路径读取。环境变量 ARTEX_EVIDENCE_HMAC_KEY 以前被
# 当成「密钥文件路径」，等于让 agent 指向自己写的文件、用自选密钥重签整个证据包
# （审计发现的真实绕过）；现在不再接受任何环境变量形式的密钥材料。
#
# ARTEX_EVIDENCE_TEST_ROOT 仅用于测试：把密钥与令牌重定位到一个临时目录。
# 它不会削弱真实威胁模型——封印挡的是「只有 Write/Edit、没有 Bash」的伪造；
# 能执行 Bash 的 agent 本来就是 root，可以直接读生产密钥文件，这一点在文件头
# 已如实说明，属于同容器内的已知上限，而不是本模块的边界。
TEST_ROOT_ENV = "ARTEX_EVIDENCE_TEST_ROOT"


def _runtime_root() -> str:
    root = (os.environ.get(TEST_ROOT_ENV) or "").strip()
    if root:
        os.makedirs(root, mode=0o700, exist_ok=True)
        return root
    return ""


def _fixed_path(filename: str, runtime_default: str) -> str:
    """固定路径列表（不含任何 agent 可控的环境变量）。

    HMAC key must survive image rebuild; otherwise old packs fail and new packs
    silently use a fresh key.
    """
    test_root = _runtime_root()
    if test_root:
        return os.path.join(test_root, filename)
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join("/app/data/evidence", filename),
        os.path.join(here, filename),
        runtime_default,
    ):
        if os.path.isfile(candidate):
            return candidate
    return os.path.join("/app/data/evidence", filename)


KEY_PATH = _fixed_path(".hmac-key", "/usr/local/share/artex-src/.evidence-hmac-key")
SEAL_NAME = "seal.json"
# 记录器身份令牌：只有 http_evidence_record / browser_xss_evidence 能拿到。
# 直接调 CLI `evidence_seal.py seal` 时环境里没有它 → 拒绝封印。
RECORDER_TOKEN_ENV = "ARTEX_EVIDENCE_RECORDER_TOKEN"


def recorder_token_path() -> str:
    """令牌文件路径：生产环境固定为 root-only 路径，测试可重定位。"""
    test_root = _runtime_root()
    if test_root:
        return os.path.join(test_root, ".recorder-token")
    return "/usr/local/share/artex-src/.recorder-token"


RECORDER_TOKEN_PATH = recorder_token_path()
# 证据时效：超过该秒数的 case 一律不算「当前状态」
MAX_CASE_AGE_SEC = int(os.environ.get("ARTEX_EVIDENCE_MAX_AGE_SEC", str(2 * 60 * 60)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_key() -> bytes:
    os.makedirs(os.path.dirname(KEY_PATH) or ".", exist_ok=True)
    if not os.path.isfile(KEY_PATH):
        fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, os.urandom(32).hex().encode("ascii"))
        finally:
            os.close(fd)
    with open(KEY_PATH, "rb") as f:
        raw = f.read().strip()
    if len(raw) < 32:
        raise RuntimeError("evidence hmac key too short")
    return raw


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict[str, Any]) -> str:
    return hmac.new(get_key(), canonical(payload), hashlib.sha256).hexdigest()


def verify_mac(payload: dict[str, Any], mac: str) -> bool:
    if not mac or not isinstance(mac, str):
        return False
    expect = sign_payload(payload)
    return hmac.compare_digest(expect, mac)


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def case_canonical(case_dir: str) -> dict[str, Any]:
    meta_path = os.path.join(case_dir, "meta.json")
    body_path = os.path.join(case_dir, "response.body")
    hdr_path = os.path.join(case_dir, "response_headers.txt")
    req_path = os.path.join(case_dir, "request.txt")
    shot_path = os.path.join(case_dir, "screenshot.png")
    meta: dict[str, Any] = {}
    if os.path.isfile(meta_path):
        try:
            meta = load_json(meta_path)
        except Exception:
            meta = {}
    req = meta.get("request") or {}
    resp = meta.get("response") or {}
    headers = req.get("headers_redacted") or {}
    dialogs = meta.get("dialogs") or []
    return {
        "v": 2,
        "kind": "browser-xss" if meta.get("dialog_executed") is not None or meta.get("kind") == "browser-xss" else "http",
        "body_sha256": sha256_file(body_path),
        "body_len": os.path.getsize(body_path) if os.path.isfile(body_path) else 0,
        "headers_sha256": sha256_file(hdr_path),
        "request_sha256": sha256_file(req_path),
        "screenshot_sha256": sha256_file(shot_path),
        "status": resp.get("status"),
        "url": req.get("url") or meta.get("url"),
        "method": req.get("method"),
        "ua": headers.get("User-Agent") or headers.get("user-agent"),
        "dialog_executed": meta.get("dialog_executed"),
        "dialog_messages": [str(d.get("message")) for d in dialogs if isinstance(d, dict) and d.get("message") is not None],
        "checks_pass": meta.get("checks_pass"),
        # v2：把「谁记的、什么时候记的」纳入封印，挡住旧证据重放与手写 meta
        "ts": meta.get("ts"),
        "recorder": meta.get("recorder"),
        "recorder_seq": meta.get("recorder_seq"),
        "request_sha_present": bool(os.path.isfile(req_path)),
    }


def recorder_token() -> str:
    """读取记录器令牌（只存在于容器内 root-only 文件）。"""
    try:
        with open(RECORDER_TOKEN_PATH, "rb") as f:
            return f.read().strip().decode("ascii", "replace")
    except Exception:
        return ""


def recorder_authorized() -> bool:
    """只有记录器进程能封印：环境变量里的令牌必须与 root-only 文件一致。"""
    env_tok = (os.environ.get(RECORDER_TOKEN_ENV) or "").strip()
    file_tok = recorder_token()
    if not env_tok or not file_tok:
        return False
    return hmac.compare_digest(env_tok, file_tok)


def seal_case(case_dir: str, force: bool = False) -> dict[str, Any]:
    case_dir = os.path.abspath(case_dir)
    # 封印入口本身也必须验身份：只靠 CLI 检查等于把「库函数」留给 agent 直调。
    if not recorder_authorized():
        raise PermissionError(
            "seal_case 只允许记录器调用：缺少 ARTEX_EVIDENCE_RECORDER_TOKEN "
            "或与 root-only 令牌文件不一致。请用 http_evidence_record / browser_xss_evidence。"
        )
    payload = case_canonical(case_dir)
    doc = {
        "payload": payload,
        "hmac_sha256": sign_payload(payload),
        "alg": "HMAC-SHA256",
        "ts": _now(),
        "tool": "artex-evidence-seal/3",
        "recorder_authorized": recorder_authorized(),
    }
    path = os.path.join(case_dir, SEAL_NAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return doc


def verify_case(case_dir: str) -> tuple[bool, str]:
    case_dir = os.path.abspath(case_dir)
    path = os.path.join(case_dir, SEAL_NAME)
    if not os.path.isfile(path):
        return False, "unsigned: missing seal.json (must be written by http_evidence_record / browser_xss_evidence)"
    try:
        doc = load_json(path)
    except Exception as e:
        return False, f"seal.json unreadable: {e}"
    payload = doc.get("payload")
    mac = doc.get("hmac_sha256")
    if not isinstance(payload, dict):
        return False, "seal payload missing"
    if not verify_mac(payload, mac if isinstance(mac, str) else ""):
        return False, "seal hmac mismatch (forged or wrong key)"
    live = case_canonical(case_dir)
    if live != payload:
        return False, "seal payload != current files (body/meta/screenshot tampered after record)"
    # 记录器身份：旧版（v1）封印与无记录器指纹的一律不认
    if payload.get("v") != 2:
        return False, "legacy seal v1: re-record with the current recorder"
    if payload.get("recorder") != "artex-recorder/2" or not payload.get("recorder_seq"):
        return False, "seal not produced by a real recorder (hand-written meta.json + direct seal)"
    # 记录器授权标记也必须在封印里为 true；否则说明封印是绕过记录器写出来的
    if doc.get("recorder_authorized") is not True:
        return False, "seal 不是由已授权记录器写入的（recorder_authorized != true）"
    return True, "ok"


def case_age_sec(case_dir: str) -> float | None:
    """case 记录时间距今秒数；读不到 ts 返回 None。"""
    meta_path = os.path.join(case_dir, "meta.json")
    if not os.path.isfile(meta_path):
        return None
    try:
        meta = load_json(meta_path)
    except Exception:
        return None
    ts = meta.get("ts")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except Exception:
        return None


def sign_document(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = {"kind": kind, "payload": payload}
    return {
        "kind": kind,
        "payload": payload,
        "hmac_sha256": sign_payload(body),
        "alg": "HMAC-SHA256",
        "ts": _now(),
    }


def verify_document(doc: dict[str, Any] | None) -> tuple[bool, str]:
    if not isinstance(doc, dict):
        return False, "missing document"
    kind = doc.get("kind")
    payload = doc.get("payload")
    mac = doc.get("hmac_sha256")
    if not kind or not isinstance(payload, dict):
        return False, "unsigned or malformed document"
    body = {"kind": kind, "payload": payload}
    if not verify_mac(body, mac if isinstance(mac, str) else ""):
        return False, "document hmac mismatch (hand-written gate/signoff/verdict)"
    return True, "ok"


def verify_pack_cases(outdir: str) -> dict[str, Any]:
    cases_dir = os.path.join(outdir, "cases")
    results = []
    all_ok = True
    if not os.path.isdir(cases_dir):
        return {"ok": False, "results": [], "reason": "no cases/"}
    for name in sorted(os.listdir(cases_dir)):
        d = os.path.join(cases_dir, name)
        if not os.path.isdir(d):
            continue
        ok, reason = verify_case(d)
        results.append({"name": name, "ok": ok, "reason": reason})
        if not ok:
            all_ok = False
    return {"ok": all_ok, "results": results}


# ---------- pack.json 封印（防止改写 pack.json 改变 lab 判定 / case 归属） ----------

PACK_SEAL_NAME = "pack.seal.json"


def pack_canonical(outdir: str) -> dict[str, Any]:
    """pack.json 的规范化摘要：只覆盖有安全意义的字段。

    v2 额外纳入截图哈希和 dialog 消息，避免只改 pack 里的 dialog_executed
    或换掉 screenshot.png 后旧封印仍然有效。
    """
    pack_path = os.path.join(outdir, "pack.json")
    cases = []
    if os.path.isfile(pack_path):
        try:
            pack = load_json(pack_path)
        except Exception:
            pack = {}
        for c in pack.get("cases") or []:
            name = c.get("name") or ""
            cdir = c.get("dir") or os.path.join(outdir, "cases", name)
            shot = os.path.join(cdir, "screenshot.png")
            dialogs = c.get("dialogs") or []
            cases.append(
                {
                    "name": name,
                    "url": c.get("url"),
                    "status": c.get("status"),
                    "method": c.get("method"),
                    "body_sha256": c.get("body_sha256"),
                    "kind": c.get("kind"),
                    "dialog_executed": c.get("dialog_executed"),
                    "dialog_messages": [
                        str(d.get("message"))
                        for d in dialogs
                        if isinstance(d, dict) and d.get("message") is not None
                    ],
                    "screenshot_sha256": sha256_file(shot),
                }
            )
        cases.sort(key=lambda x: str(x.get("name")))
        compares = [
            {"attack": c.get("attack"), "control": c.get("control"), "pass": c.get("pass")}
            for c in (pack.get("compares") or [])
        ]
        compares.sort(key=lambda x: (str(x.get("attack")), str(x.get("control"))))
    else:
        compares = []
    return {"v": 2, "pack_sha256": sha256_file(pack_path), "cases": cases, "compares": compares}


def seal_pack(outdir: str) -> dict[str, Any]:
    outdir = os.path.abspath(outdir)
    payload = pack_canonical(outdir)
    doc = {
        "kind": "pack",
        "payload": payload,
        "hmac_sha256": sign_payload(payload),
        "alg": "HMAC-SHA256",
        "ts": _now(),
        "tool": "artex-evidence-seal/3",
    }
    path = os.path.join(outdir, PACK_SEAL_NAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return doc


def verify_pack(outdir: str) -> tuple[bool, str]:
    outdir = os.path.abspath(outdir)
    path = os.path.join(outdir, PACK_SEAL_NAME)
    if not os.path.isfile(path):
        return False, "unsigned: missing pack.seal.json (pack.json rewritten by hand?)"
    try:
        doc = load_json(path)
    except Exception as e:
        return False, f"pack.seal.json unreadable: {e}"
    payload = doc.get("payload")
    mac = doc.get("hmac_sha256")
    if not isinstance(payload, dict):
        return False, "pack seal payload missing"
    if not verify_mac(payload, mac if isinstance(mac, str) else ""):
        return False, "pack seal hmac mismatch (pack.json tampered)"
    live = pack_canonical(outdir)
    if payload.get("v") != 2:
        return False, "legacy pack seal v1: re-record so screenshot/dialog hashes are covered"
    if live != payload:
        return False, "pack seal payload != current pack.json (cases/urls/compares/screenshot changed after record)"
    return True, "ok"


def audit(event: str, **kw: Any) -> None:
    path = os.environ.get("ARTEX_EVIDENCE_AUDIT", "/app/data/evidence/_audit.jsonl")
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        rec = {"ts": _now(), "event": event, **kw}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    except Exception:
        pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["seal", "verify", "verify-pack", "seal-pack", "verify-packfile"])
    p.add_argument("--case-dir", default="")
    p.add_argument("--outdir", default="")
    args = p.parse_args()
    if args.cmd == "seal":
        if not args.case_dir:
            print("ERROR: --case-dir", file=sys.stderr)
            return 2
        if not recorder_authorized():
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "seal 只允许记录器调用：缺少 ARTEX_EVIDENCE_RECORDER_TOKEN 或与令牌文件不一致。"
                        " 手写 meta.json 后直接 seal 不被接受；请用 http_evidence_record / browser_xss_evidence。",
                    },
                    ensure_ascii=False,
                ),
                file=sys.stderr,
            )
            return 3
        print(json.dumps(seal_case(args.case_dir), indent=2))
        return 0
    if args.cmd == "verify":
        ok, reason = verify_case(args.case_dir)
        print(json.dumps({"ok": ok, "reason": reason}))
        return 0 if ok else 1
    if args.cmd == "seal-pack":
        if not args.outdir:
            print("ERROR: --outdir", file=sys.stderr)
            return 2
        if not recorder_authorized():
            print(json.dumps({"ok": False, "error": "seal-pack 只允许记录器调用"}, ensure_ascii=False), file=sys.stderr)
            return 3
        print(json.dumps(seal_pack(args.outdir), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "verify-packfile":
        ok, reason = verify_pack(args.outdir)
        print(json.dumps({"ok": ok, "reason": reason}))
        return 0 if ok else 1
    out = verify_pack_cases(args.outdir)
    print(json.dumps(out, indent=2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
