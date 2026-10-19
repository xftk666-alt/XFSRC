#!/usr/bin/env python3
"""对抗测试：闸门必须挡住谎报/误报/手改文件。失败即非零退出。"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = ["python3", f"{ROOT}/retest_strict.py"]
REC = ["python3", f"{ROOT}/http_evidence.py"]
GATE_EG = ["python3", f"{ROOT}/evidence_gate.py"]
SCOPE = ["python3", f"{ROOT}/scope_check.py"]
COV_REC = ["python3", f"{ROOT}/coverage_record.py"]
COV_REP = ["python3", f"{ROOT}/coverage_report.py"]

# 新增闸门模块必须在导入路径里
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0
ERRORS: list[str] = []


def run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def parse(proc: subprocess.CompletedProcess) -> dict:
    txt = proc.stdout.strip() or proc.stderr.strip()
    try:
        return json.loads(txt[txt.find("{") :])
    except Exception:
        return {"_raw": txt, "_err": proc.stderr, "_code": proc.returncode}


def expect(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        ERRORS.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: ARG002
        return

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        auth = self.headers.get("Authorization", "")
        authed = auth.startswith("Bearer ") and len(auth.strip()) > 8
        if path == "/api/Users/37":
            if authed:
                body = b'{"id":37,"email":"victim-b@test.example","role":"customer"}\n'
                self._send(200, body)
                return
            self._send(401, b'{"error":"unauthorized"}\n')
            return
        if path == "/api/Users/1":
            if authed:
                body = b'{"id":1,"email":"attacker-a@test.example","role":"customer"}\n'
                self._send(200, body)
                return
            self._send(401, b'{"error":"unauthorized"}\n')
            return
        if path == "/echo":
            body = json.dumps({"echo": qs}).encode() + b"\n"
            self._send(200, body)
            return
        if path == "/":
            self._send(200, b"<!doctype html><html><body id=\"root\">spa home</body></html>\n")
            return
        if path == "/.git/HEAD":
            self._send(200, b"<!doctype html><html><body id=\"root\">spa home</body></html>\n")
            return
        if path == "/ftp":
            self._send(200, b"Index of /ftp\nacquisitions.md\nencrypt.pyc\n")
            return
        self._send(404, b"not found")

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server() -> tuple[socketserver.TCPServer, int]:
    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    port = httpd.server_address[1]
    return httpd, port


def record(outdir: str, name: str, url: str, bearer: str = "", expect_contains: str = "", expect_status: str = "") -> dict:
    cmd = REC + ["record", "--outdir", outdir, "--name", name, "--url", url, "--method", "GET"]
    if bearer:
        cmd += ["--bearer", bearer]
    if expect_contains:
        cmd += ["--expect-contains", expect_contains]
    if expect_status:
        cmd += ["--expect-status", expect_status]
    p = run(cmd)
    return parse(p)


def compare(outdir: str, attack: str, control: str, **kw: str) -> dict:
    cmd = REC + ["compare", "--outdir", outdir, "--attack", attack, "--control", control]
    for k, v in kw.items():
        cmd += [f"--{k.replace('_', '-')}", v]
    return parse(run(cmd))


def gate(outdir: str, marker: str, kind: str = "idor", attack: str = "attack-read-b", control: str = "control-unauth") -> tuple[int, dict]:
    p = run(PY + ["gate", "--outdir", outdir, "--kind", kind, "--victim-marker", marker, "--attack", attack, "--control", control])
    return p.returncode, parse(p)


def verdict(outdir: str, v: str, advice: str = "needs-human", marker: str = "", summary: str = "t") -> tuple[int, dict]:
    cmd = PY + ["verdict", "--outdir", outdir, "--verdict", v, "--submit-advice", advice, "--summary", summary]
    if marker:
        cmd += ["--victim-marker", marker, "--kind", "idor", "--attack", "attack-read-b", "--control", "control-unauth"]
    p = run(cmd)
    return p.returncode, parse(p)


def signoff(outdir: str, phrase: str) -> tuple[int, dict]:
    p = run(PY + ["signoff", "--outdir", outdir, "--phrase", phrase])
    return p.returncode, parse(p)


def make_idor_pack(base: str, port: int) -> str:
    out = os.path.join(base, "idor")
    os.makedirs(out, exist_ok=True)
    record(out, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN", "victim-b@test.example", "200")
    record(out, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37", "", "", "401")
    record(out, "control-self", f"http://127.0.0.1:{port}/api/Users/1", "ATOKEN", "attacker-a@test.example", "200")
    compare(
        out,
        "attack-read-b",
        "control-unauth",
        attack_status="200",
        control_status="401",
        attack_contains="victim-b@test.example",
        bodies_differ="true",
    )
    return out


def main() -> int:
    httpd, port = start_server()
    tmp = tempfile.mkdtemp(prefix="retest-adv-")
    print(f"tmp={tmp} port={port}")
    try:
        # 1 genuine IDOR
        print("\n[1] genuine IDOR pack")
        out = make_idor_pack(tmp, port)
        rc, g = gate(out, "victim-b@test.example")
        expect("genuine_gate_ok", rc == 0 and g.get("ok") is True, str(g.get("reasons")))
        expect("genuine_is_lab", g.get("lab") is True, "127.0.0.1 should be lab")
        expect("genuine_advice_never", g.get("submit_advice") == "never", str(g.get("submit_advice")))
        expect("challenge_present", bool(g.get("challenge")) and len(str(g.get("challenge"))) == 12, str(g.get("challenge")))
        expect("hmac_on_gate", bool(g.get("hmac_sha256")), "gate stdout missing hmac")
        rc, v = verdict(out, "reproduced", "needs-human", "victim-b@test.example")
        expect("genuine_reproduced_ok", rc == 0 and v.get("ok") is True, str(v))
        expect("genuine_reproduced_never", v.get("submit_advice") == "never", str(v.get("submit_advice")))
        rc, v = verdict(out, "reproduced", "ready", "victim-b@test.example")
        expect("lab_ready_rejected", rc != 0 and v.get("rejected") is True, str(v.get("errors")))

        # 2 generic marker
        print("\n[2] generic marker 200")
        rc, g = gate(out, "200")
        expect("generic_marker_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        # 3 control also has marker (own data)
        print("\n[3] marker in both attack and control")
        rc, g = gate(out, "role")
        # "role" is GENERIC word
        expect("generic_role_fail", rc != 0, str(g.get("reasons")))
        rc, g = gate(out, "customer")
        expect("generic_customer_fail", rc != 0, str(g.get("reasons")))

        # 4 tamper body after seal
        print("\n[4] tamper response.body after seal")
        tamper = os.path.join(tmp, "tamper")
        shutil.copytree(out, tamper)
        body = Path(tamper) / "cases" / "attack-read-b" / "response.body"
        body.write_bytes(b'{"id":37,"email":"victim-b@test.example","injected":true}\n')
        rc, g = gate(tamper, "victim-b@test.example")
        expect("tamper_body_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))
        expect(
            "tamper_mentions_seal",
            any("seal" in str(r).lower() or "tamper" in str(r).lower() or "hmac" in str(r).lower() for r in (g.get("reasons") or []) + [str(g)]),
            str(g.get("reasons")),
        )

        # 5 hand-written gate.json
        print("\n[5] hand-written gate.json ok=true")
        fake = os.path.join(tmp, "fake-gate")
        shutil.copytree(out, fake)
        Path(fake, "gate.json").write_text(json.dumps({"ok": True, "fingerprint": "deadbeef", "challenge": "aaaaaaaaaaaa", "lab": False}))
        rc, v = verdict(fake, "reproduced", "needs-human", "victim-b@test.example")
        # live re-eval should still pass because pack is genuine, but lab never ready.
        # The point: reproduced without live marker used to trust disk. Now with marker it re-evaluates.
        # Without marker:
        rc2, v2 = verdict(fake, "reproduced", "needs-human", "")
        expect("handwritten_gate_without_marker_rejected", rc2 != 0, str(v2))

        # 6 unsigned case (hand-written body)
        print("\n[6] unsigned hand-written pack")
        un = os.path.join(tmp, "unsigned")
        os.makedirs(os.path.join(un, "cases", "attack-read-b"))
        os.makedirs(os.path.join(un, "cases", "control-unauth"))
        Path(un, "cases", "attack-read-b", "response.body").write_bytes(b'{"email":"victim-b@test.example"}')
        Path(un, "cases", "control-unauth", "response.body").write_bytes(b'{"error":"unauthorized"}')
        meta_a = {
            "name": "attack-read-b",
            "request": {"method": "GET", "url": "http://example.com/api/Users/37", "headers_redacted": {"User-Agent": "artex-http-evidence/1.0"}},
            "response": {"status": 200, "body_sha256": hashlib.sha256(b'{"email":"victim-b@test.example"}').hexdigest(), "body_len": 36},
            "checks_pass": True,
        }
        Path(un, "cases", "attack-read-b", "meta.json").write_text(json.dumps(meta_a))
        meta_c = dict(meta_a)
        meta_c["name"] = "control-unauth"
        meta_c["response"] = {"status": 401, "body_sha256": hashlib.sha256(b'{"error":"unauthorized"}').hexdigest(), "body_len": 24}
        Path(un, "cases", "control-unauth", "meta.json").write_text(json.dumps(meta_c))
        cmp = {
            "attack": "attack-read-b",
            "control": "control-unauth",
            "pass": True,
            "checks": [
                {"name": "attack_status", "pass": True},
                {"name": "attack_contains", "pass": True, "expected": "victim-b@test.example"},
            ],
        }
        cmp_path = os.path.join(un, "compare-attack-read-b-vs-control-unauth.json")
        Path(cmp_path).write_text(json.dumps(cmp))
        pack = {
            "cases": [
                {"name": "attack-read-b", "status": 200, "url": "https://real-program.example/api/Users/37", "body_sha256": meta_a["response"]["body_sha256"]},
                {"name": "control-unauth", "status": 401, "url": "https://real-program.example/api/Users/37", "body_sha256": meta_c["response"]["body_sha256"]},
            ],
            "compares": [{"attack": "attack-read-b", "control": "control-unauth", "pass": True, "file": cmp_path}],
        }
        Path(un, "pack.json").write_text(json.dumps(pack))
        rc, g = gate(un, "victim-b@test.example")
        expect("unsigned_pack_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        # 7 status-only compare on genuine-like unsigned? use recorded pack without field compare
        print("\n[7] status-only compare")
        st = os.path.join(tmp, "status-only")
        os.makedirs(st)
        record(st, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN")
        record(st, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37")
        compare(st, "attack-read-b", "control-unauth", attack_status="200", control_status="401")
        rc, g = gate(st, "victim-b@test.example")
        expect("status_only_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        # 8 SPA fallback
        print("\n[8] SPA fallback .git == homepage")
        spa = os.path.join(tmp, "spa")
        os.makedirs(spa)
        record(spa, "attack-git", f"http://127.0.0.1:{port}/.git/HEAD")
        record(spa, "control-home", f"http://127.0.0.1:{port}/")
        compare(spa, "attack-git", "control-home", attack_contains="ref: refs", bodies_differ="true")
        rc, g = gate(spa, "ref: refs", kind="info", attack="attack-git", control="control-home")
        expect("spa_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))
        expect(
            "spa_not_a_vuln",
            g.get("recommended_verdict") == "not_a_vuln" or any("SPA" in str(r) for r in (g.get("reasons") or [])),
            str(g.get("recommended_verdict")) + str(g.get("reasons")),
        )

        # 9 info leak genuine /ftp
        print("\n[9] genuine listing vs homepage")
        ftp = os.path.join(tmp, "ftp")
        os.makedirs(ftp)
        record(ftp, "attack-ftp", f"http://127.0.0.1:{port}/ftp", expect_contains="acquisitions.md")
        record(ftp, "control-home", f"http://127.0.0.1:{port}/")
        compare(ftp, "attack-ftp", "control-home", attack_contains="acquisitions.md", bodies_differ="true")
        rc, g = gate(ftp, "acquisitions.md", kind="info", attack="attack-ftp", control="control-home")
        expect("ftp_gate_ok", rc == 0 and g.get("ok") is True, str(g.get("reasons")))
        expect("ftp_still_never", g.get("submit_advice") == "never", str(g.get("submit_advice")))

        # 10 signoff without challenge / lab
        print("\n[10] signoff")
        rc, s = signoff(out, "approve")
        expect("bad_phrase_fail", rc != 0, str(s))
        rc, s = signoff(out, "我已核验证据包并批准提交")
        expect("phrase_without_challenge_fail", rc != 0, str(s))
        # even with challenge, lab forbidden
        gfile = json.loads(Path(out, "gate.json").read_text())
        ch = (gfile.get("payload") or {}).get("challenge") or gfile.get("challenge")
        rc, s = signoff(out, f"我已核验证据包并批准提交 {ch}")
        expect("lab_signoff_fail", rc != 0, str(s))

        # 11 forged signoff.json
        print("\n[11] forged signoff.json")
        Path(out, "signoff.json").write_text(json.dumps({"ok": True, "phrase_ok": True, "hmac_sha256": "00" * 32, "payload": {"ok": True, "fingerprint": "x", "challenge": "x"}}))
        rc, v = verdict(out, "reproduced", "ready", "victim-b@test.example")
        expect("forged_signoff_ready_fail", rc != 0, str(v))

        # 12 evidence_gate also rejects unsigned
        print("\n[12] evidence_gate unsigned")
        p = run(GATE_EG + [un])
        eg = parse(p)
        expect("evidence_gate_unsigned_fail", p.returncode != 0 and eg.get("ok") is False, str(eg))

        # 13 evidence_gate status-only
        print("\n[13] evidence_gate status-only")
        p = run(GATE_EG + [st])
        eg = parse(p)
        expect("evidence_gate_status_only_fail", p.returncode != 0 and eg.get("ok") is False, str(eg))

        # 14 not_a_vuln allowed without marker
        print("\n[14] not_a_vuln verdict")
        rc, v = verdict(spa, "not_a_vuln", "never", "")
        expect("not_a_vuln_ok", rc == 0 and v.get("verdict") == "not_a_vuln", str(v))
        expect("not_a_vuln_never", v.get("submit_advice") == "never", str(v.get("submit_advice")))

        # 15 compare bound to wrong string
        print("\n[15] compare contains unrelated string")
        wrong = os.path.join(tmp, "wrong-contains")
        os.makedirs(wrong)
        record(wrong, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN")
        record(wrong, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37")
        compare(wrong, "attack-read-b", "control-unauth", attack_contains="customer", bodies_differ="true")
        rc, g = gate(wrong, "victim-b@test.example")
        expect("unrelated_contains_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        # 16 live HTTP record produced seal.json
        print("\n[16] recorder writes seal.json")
        seal_p = Path(out) / "cases" / "attack-read-b" / "seal.json"
        expect("seal_written", seal_p.is_file(), str(seal_p))
        if seal_p.is_file():
            seal = json.loads(seal_p.read_text())
            expect("seal_has_hmac", bool(seal.get("hmac_sha256")), str(seal.keys()))

        print("\n[17] IDOR missing control-self")
        noself = os.path.join(tmp, "no-self")
        os.makedirs(noself)
        record(noself, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN", "victim-b@test.example", "200")
        record(noself, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37", "", "", "401")
        compare(noself, "attack-read-b", "control-unauth", attack_status="200", control_status="401", attack_contains="victim-b@test.example", bodies_differ="true")
        rc, g = gate(noself, "victim-b@test.example")
        expect("idor_without_self_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        print("\n[18] control-self has same marker (own data)")
        own = os.path.join(tmp, "own-data")
        os.makedirs(own)
        record(own, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/1", "ATOKEN", "attacker-a@test.example", "200")
        record(own, "control-unauth", f"http://127.0.0.1:{port}/api/Users/1", "", "", "401")
        record(own, "control-self", f"http://127.0.0.1:{port}/api/Users/1", "ATOKEN", "attacker-a@test.example", "200")
        compare(own, "attack-read-b", "control-unauth", attack_contains="attacker-a@test.example", bodies_differ="true")
        rc, g = gate(own, "attacker-a@test.example")
        expect("own_data_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        print("\n[19] marker echoed from request")
        echo = os.path.join(tmp, "echo")
        os.makedirs(echo)
        marker = "victim-b@test.example"
        record(echo, "attack-read-b", f"http://127.0.0.1:{port}/echo?q={marker}")
        record(echo, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37")
        compare(echo, "attack-read-b", "control-unauth", attack_contains=marker, bodies_differ="true")
        rc, g = gate(echo, marker, kind="info", attack="attack-read-b", control="control-unauth")
        expect("echo_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        print("\n[20] different origin")
        httpd2, port2 = start_server()
        try:
            diff = os.path.join(tmp, "diff-origin")
            os.makedirs(diff)
            record(diff, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN")
            record(diff, "control-unauth", f"http://127.0.0.1:{port2}/api/Users/37")
            record(diff, "control-self", f"http://127.0.0.1:{port}/api/Users/1", "ATOKEN")
            compare(diff, "attack-read-b", "control-unauth", attack_contains="victim-b@test.example", bodies_differ="true")
            rc, g = gate(diff, "victim-b@test.example")
            expect("diff_origin_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))
        finally:
            httpd2.server_close()

        print("\n[21] unpaired compare")
        unp = os.path.join(tmp, "unpaired")
        os.makedirs(unp)
        record(unp, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", "ATOKEN")
        record(unp, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37")
        record(unp, "control-self", f"http://127.0.0.1:{port}/api/Users/1", "ATOKEN")
        compare(unp, "attack-read-b", "control-self", attack_contains="victim-b@test.example", bodies_differ="true")
        rc, g = gate(unp, "victim-b@test.example", attack="attack-read-b", control="control-unauth")
        expect("unpaired_compare_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        print("\n[22] tamper request.txt")
        tamper_req = os.path.join(tmp, "tamper-req")
        shutil.copytree(out, tamper_req)
        reqp = Path(tamper_req) / "cases" / "attack-read-b" / "request.txt"
        reqp.write_text(reqp.read_text() + "\nX-Injected: 1\n")
        rc, g = gate(tamper_req, "victim-b@test.example")
        expect("tamper_request_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

        print("\n[23] stale JWT")
        def mint_jwt(iat):
            def b64(obj):
                raw = json.dumps(obj, separators=(",", ":")).encode()
                return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
            return f"{b64({'alg':'none'})}.{b64({'iat': iat, 'sub': 'a'})}."
        stale = os.path.join(tmp, "stale-jwt")
        os.makedirs(stale)
        old = mint_jwt(int(time.time()) - 3 * 24 * 3600)
        record(stale, "attack-read-b", f"http://127.0.0.1:{port}/api/Users/37", old, "victim-b@test.example", "200")
        record(stale, "control-unauth", f"http://127.0.0.1:{port}/api/Users/37", "", "", "401")
        record(stale, "control-self", f"http://127.0.0.1:{port}/api/Users/1", old, "attacker-a@test.example", "200")
        compare(stale, "attack-read-b", "control-unauth", attack_contains="victim-b@test.example", bodies_differ="true")
        rc, g = gate(stale, "victim-b@test.example")
        expect("stale_jwt_fail", rc != 0 and g.get("ok") is False, str(g.get("reasons")))

    finally:
        httpd.shutdown()

    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    for e in ERRORS:
        print(" -", e)
    Path("/app/data/sessions/conv-34/retest-adversarial-results.json").write_text(
        json.dumps({"pass": PASS, "fail": FAIL, "errors": ERRORS}, indent=2)
    )
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
