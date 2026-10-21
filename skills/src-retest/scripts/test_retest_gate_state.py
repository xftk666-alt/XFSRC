#!/usr/bin/env python3
"""闸门状态机回归：ready 可达、fixed 必须带证据、compare 不可伪造。

这三条都是审计发现的真实缺陷，且用「127.0.0.1」测试服务器无法覆盖
（loopback 恒为靶场，ready 永远被拒），所以这里直接构造一个由记录器封印、
指向公网资产的证据包，再跑真实的 CLI。

失败即非零退出；不依赖 /app，可在任意目录运行。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PY = ["python3", os.path.join(ROOT, "retest_strict.py")]
PUBLIC_HOST = "portal.mybank-online.com"
MARKER = "victim-b@mybank-online.com"
ATTACK = "attack-read-b"
CONTROL = "control-unauth"
SELF = "control-self"

PASS = 0
FAIL = 0
ERRORS: list[str] = []

# The seal module resolves the key/token paths at import time, so the test runtime
# root must be in place before `import evidence_seal`.
TMP = tempfile.mkdtemp(prefix="retest-state-")


def expect(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        ERRORS.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def parse(p: subprocess.CompletedProcess) -> dict:
    txt = p.stdout.strip() or p.stderr.strip()
    try:
        return json.loads(txt[txt.find("{"):])
    except Exception:
        return {"_raw": txt, "_code": p.returncode}


def bootstrap_runtime(tmp: str) -> None:
    """Relocate the HMAC key + recorder token into the test temp dir."""
    root = os.path.join(tmp, "runtime")
    os.makedirs(root, mode=0o700, exist_ok=True)
    key = os.path.join(root, ".hmac-key")
    if not os.path.isfile(key):
        with open(key, "w", encoding="utf-8") as f:
            f.write("a" * 64)
        os.chmod(key, 0o600)
    token = os.path.join(root, ".recorder-token")
    if not os.path.isfile(token):
        with open(token, "w", encoding="utf-8") as f:
            f.write("test-recorder-token")
        os.chmod(token, 0o600)
    os.environ["ARTEX_EVIDENCE_TEST_ROOT"] = root
    os.environ["ARTEX_EVIDENCE_RECORDER_TOKEN"] = "test-recorder-token"


bootstrap_runtime(TMP)
import evidence_seal as es  # noqa: E402  (must follow bootstrap_runtime)


def write_case(outdir: str, name: str, path: str, status: int, body: str, auth: str) -> None:
    """Lay down one recorder-produced case and seal it."""
    case = os.path.join(outdir, "cases", name)
    os.makedirs(case, exist_ok=True)
    url = f"https://{PUBLIC_HOST}{path}"
    hdrs = f"GET {path} HTTP/1.1\nHost: {PUBLIC_HOST}\n"
    if auth:
        hdrs += f"Authorization: Bearer {auth}\n"
    with open(os.path.join(case, "request.txt"), "w", encoding="utf-8") as f:
        f.write(hdrs)
    with open(os.path.join(case, "response_headers.txt"), "w", encoding="utf-8") as f:
        f.write(f"HTTP/1.1 {status} X\nContent-Type: application/json\n")
    with open(os.path.join(case, "response.body"), "w", encoding="utf-8") as f:
        f.write(body)
    meta = {
        "ts": es._now(),
        "recorder": "artex-recorder/2",
        "recorder_seq": 1,
        "kind": "http",
        "url": url,
        "request": {
            "url": url,
            "method": "GET",
            "headers_redacted": {"User-Agent": "artex-http-evidence/1.0"},
        },
        "response": {"status": status},
    }
    with open(os.path.join(case, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    es.seal_case(case)


def write_compare(outdir: str, pass_flag: bool) -> None:
    doc = {
        "attack": ATTACK,
        "control": CONTROL,
        "pass": pass_flag,
        "checks": [
            {"name": "attack_contains", "expected": MARKER, "pass": pass_flag},
            {"name": "attack_status", "expected": 200 if pass_flag else 403, "pass": True},
            {"name": "control_status", "expected": 401, "pass": True},
            {"name": "bodies_differ", "expected": True, "pass": True},
        ],
    }
    with open(os.path.join(outdir, f"compare-{ATTACK}-vs-{CONTROL}.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f)


def compare_entry(outdir: str, pass_flag: bool) -> dict:
    """pack.compares 条目：file 必须是绝对路径（与记录器写出的一致）。"""
    return {
        "attack": ATTACK,
        "control": CONTROL,
        "pass": pass_flag,
        "file": os.path.join(outdir, f"compare-{ATTACK}-vs-{CONTROL}.json"),
    }


def write_pack(outdir: str, compares: list[dict], cases: dict[str, str]) -> None:
    """cases: name -> request path (the URL decides the SPA-fallback check)."""
    pack = {
        "cases": [
            {
                "name": n,
                "dir": os.path.join(outdir, "cases", n),
                "url": f"https://{PUBLIC_HOST}{path}",
                "status": 200,
                "method": "GET",
                "kind": "http",
            }
            for n, path in cases.items()
        ],
        "compares": compares,
    }
    with open(os.path.join(outdir, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(pack, f)
    es.seal_pack(outdir)


def build_pack(outdir: str, compare_pass: bool = True) -> None:
    write_case(outdir, ATTACK, "/api/Users/37", 200, json.dumps({"id": 37, "email": MARKER}), "ATOKEN")
    write_case(outdir, CONTROL, "/api/Users/37", 401, '{"error":"unauthorized"}', "")
    write_case(outdir, SELF, "/api/Users/1", 200, json.dumps({"id": 1, "email": "attacker-a@mybank-online.com"}), "ATOKEN")
    write_compare(outdir, compare_pass)
    write_pack(
        outdir,
        [compare_entry(outdir, compare_pass)],
        {ATTACK: "/api/Users/37", CONTROL: "/api/Users/37", SELF: "/api/Users/1"},
    )


def gate(outdir: str) -> tuple[int, dict]:
    p = run(PY + ["gate", "--outdir", outdir, "--kind", "idor", "--victim-marker", MARKER,
                  "--attack", ATTACK, "--control", CONTROL])
    return p.returncode, parse(p)


def signoff(outdir: str, phrase: str) -> tuple[int, dict]:
    p = run(PY + ["signoff", "--outdir", outdir, "--phrase", phrase])
    return p.returncode, parse(p)


def verdict(outdir: str, v: str, advice: str, marker: str = "") -> tuple[int, dict]:
    cmd = PY + ["verdict", "--outdir", outdir, "--verdict", v, "--submit-advice", advice, "--summary", "t"]
    if marker:
        cmd += ["--victim-marker", marker, "--kind", "idor", "--attack", ATTACK, "--control", CONTROL]
    p = run(cmd)
    return p.returncode, parse(p)


def main() -> int:
    tmp = TMP
    print(f"tmp={tmp}")

    # ---------- 1. ready 必须可达 ----------
    print("\n[1] gate -> signoff -> verdict ready")
    out = os.path.join(tmp, "ready")
    os.makedirs(out)
    build_pack(out)
    rc, g = gate(out)
    expect("ready_gate_ok", rc == 0 and g.get("ok") is True, str(g.get("reasons")))
    expect("ready_gate_not_lab", g.get("lab") is False, f"lab={g.get('lab')} (public host must not be lab)")
    ch = str(g.get("challenge") or "")
    expect("ready_challenge", len(ch) == 12, ch)

    rc, s = signoff(out, f"我已核验证据包并批准提交 {ch}")
    expect("ready_signoff_ok", rc == 0 and s.get("ok") is True, str(s))

    rc, v = verdict(out, "reproduced", "ready", MARKER)
    expect("ready_accepted", rc == 0 and v.get("ok") is True, str(v.get("errors") or v))
    expect("ready_advice", v.get("submit_advice") == "ready", str(v.get("submit_advice")))

    # 被拒的 verdict 不得毁掉已签的 gate
    gate_before = json.loads(open(os.path.join(out, "gate.json"), encoding="utf-8").read())
    verdict(out, "reproduced", "ready", "not-the-marker")
    gate_after = json.loads(open(os.path.join(out, "gate.json"), encoding="utf-8").read())
    expect("rejected_verdict_keeps_gate",
           gate_before.get("payload", {}).get("challenge") == gate_after.get("payload", {}).get("challenge"),
           "rejected verdict rewrote gate.json")

    # ---------- 2. fixed 必须带证据 ----------
    print("\n[2] fixed without evidence")
    empty = os.path.join(tmp, "empty")
    os.makedirs(empty)
    write_pack(empty, [], {})
    rc, v = verdict(empty, "fixed", "needs-human", MARKER)
    expect("fixed_empty_pack_rejected", rc != 0 and v.get("rejected") is True, str(v.get("errors")))

    still = os.path.join(tmp, "still")
    os.makedirs(still)
    build_pack(still, compare_pass=False)
    rc, v = verdict(still, "fixed", "needs-human", MARKER)
    expect("fixed_still_reproducible_rejected", rc != 0 and v.get("rejected") is True, str(v.get("errors")))

    # 真·已修复：attack 被拒且不再含 marker，control-self 正常
    fixed_dir = os.path.join(tmp, "really-fixed")
    os.makedirs(fixed_dir)
    write_case(fixed_dir, ATTACK, "/api/Users/37", 200, '{"error":"forbidden"}', "ATOKEN")
    write_case(fixed_dir, CONTROL, "/api/Users/37", 401, '{"error":"unauthorized"}', "")
    write_case(fixed_dir, SELF, "/api/Users/1", 200, json.dumps({"id": 1, "email": "attacker-a@mybank-online.com"}), "ATOKEN")
    write_compare(fixed_dir, False)
    write_pack(fixed_dir, [compare_entry(fixed_dir, False)],
               {ATTACK: "/api/Users/37", CONTROL: "/api/Users/37", SELF: "/api/Users/1"})
    rc, v = verdict(fixed_dir, "fixed", "needs-human", MARKER)
    expect("fixed_with_evidence_accepted", rc == 0 and v.get("ok") is True, str(v.get("errors") or v))

    # ---------- 3. compare 不可伪造 ----------
    print("\n[3] forged compare cannot flip gate")
    forged = os.path.join(tmp, "forged")
    os.makedirs(forged)
    build_pack(forged, compare_pass=False)
    # 手工把未封印的 compare 改成 pass=true
    write_compare(forged, True)
    rc, g = gate(forged)
    expect("forged_compare_rejected", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

    # ---------- 4. SSRF 载荷不应把真实资产判成靶场 ----------
    print("\n[4] SSRF payload on a public host is not a lab")
    ssrf = os.path.join(tmp, "ssrf")
    os.makedirs(ssrf)
    write_case(ssrf, ATTACK, "/fetch?url=http://127.0.0.1:8080/admin", 200,
               json.dumps({"internal": "root:x:0:0"}), "ATOKEN")
    write_case(ssrf, CONTROL, "/fetch?url=http://127.0.0.1:8080/admin", 403, '{"error":"forbidden"}', "")
    write_case(ssrf, SELF, "/api/Users/1", 200, json.dumps({"id": 1, "email": "a@mybank-online.com"}), "ATOKEN")
    write_compare(ssrf, False)
    write_pack(ssrf, [compare_entry(ssrf, False)],
               {ATTACK: "/fetch?url=http://127.0.0.1:8080/admin", CONTROL: "/fetch?url=http://127.0.0.1:8080/admin",
                SELF: "/api/Users/1"})
    rc, g = gate(ssrf)
    expect("ssrf_not_lab", g.get("lab") is False, f"lab={g.get('lab')} (loopback in the payload is not the asset)")

    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    for e in ERRORS:
        print(" -", e)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
