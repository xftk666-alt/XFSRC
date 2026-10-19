#!/usr/bin/env python3
"""新增闸门的对抗测试（判重 / 靶场 / 定级 / scope / coverage）。

与 test_retest_adversarial.py 并列，互不改动：
  前者覆盖证据包/HMAC/复测闸门（38 例），
  本文件覆盖 2026-10-19 新增的五道闸门。

失败即非零退出。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SCOPE = ["python3", f"{ROOT}/scope_check.py"]
COV_REC = ["python3", f"{ROOT}/coverage_record.py"]
COV_REP = ["python3", f"{ROOT}/coverage_report.py"]

PASS = 0
FAIL = 0
ERRORS: list[str] = []


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def parse(p: subprocess.CompletedProcess) -> dict:
    txt = p.stdout.strip() or p.stderr.strip()
    try:
        return json.loads(txt[txt.find("{"):])
    except Exception:
        return {"_raw": txt, "_err": p.stderr, "_code": p.returncode}


def expect(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        ERRORS.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="gates-hard-")
    print(f"tmp={tmp}")

    # ---------- 判重：短路径 ----------
    print("\n[A] 判重必须覆盖短路径（/ftp /api /v1）")
    from submit_brief import lookup_task_duplicates, path_prefixes

    expect("short_path_kept", "/ftp" in path_prefixes("/ftp"), str(path_prefixes("/ftp")))
    expect("api_prefix_kept", "/api" in path_prefixes("/api/Users/37"), str(path_prefixes("/api/Users/37")))
    expect("root_dropped", "/" not in path_prefixes("/"), str(path_prefixes("/")))

    rows = [
        {"id": 7, "vulnclass": "info-disclosure", "severity": "high",
         "summary": "Unauthenticated /ftp listing and poison-null-byte file disclosure", "name": ""},
        {"id": 8, "vulnclass": "info-disclosure", "severity": "medium",
         "summary": "Unauthenticated /encryptionkeys listing exposes jwt.pub", "name": ""},
        {"id": 11, "vulnclass": "idor", "severity": "high",
         "summary": "customer can GET /api/Users list all accounts", "name": ""},
        {"id": 12, "vulnclass": "idor", "severity": "high",
         "summary": "PUT /api/Addresss/8 lets A take over B address", "name": ""},
    ]
    hits = lookup_task_duplicates("", "info-disclosure", ["172.18.0.3"], ["/ftp"], _rows=rows)
    expect("short_path_dup_hit", any(h["finding_id"] == 7 for h in hits), str(hits))
    expect("short_path_no_cross_class", not any(h["finding_id"] == 11 for h in hits), str(hits))
    hits2 = lookup_task_duplicates("", "info-disclosure", ["172.18.0.3"], ["/encryptionkeys"], _rows=rows)
    expect("long_path_dup_hit", any(h["finding_id"] == 8 for h in hits2), str(hits2))
    hits3 = lookup_task_duplicates("", "idor", ["172.18.0.3"], ["/api/Addresss/9"], _rows=rows)
    expect("api_short_prefix_hit", any(h["finding_id"] == 12 for h in hits3), str(hits3))
    expect("dup_match_reason", any(h.get("match") == "path" for h in hits), str(hits))
    # 完全对不上路径/主机时不得报重复（避免所有 IDOR 互为候选）
    hits4 = lookup_task_duplicates("", "idor", ["other.example.com"], ["/totally/different"], _rows=rows)
    expect("no_noise_when_unrelated", hits4 == [], str(hits4))

    # ---------- 靶场识别 ----------
    print("\n[B] 靶场识别必须覆盖 RFC1918 / 保留后缀 / 单标签")
    import lab_detect

    lab_hosts = [
        "10.10.10.5", "192.168.1.20", "10.129.14.7", "172.18.0.3", "127.0.0.1",
        "vuln.local", "app.internal", "shop.test", "target.htb", "juice-shop",
        "169.254.169.254", "192.0.2.10", "example.com", "app.example.com",
        "internal.corp", "foo", "[::1]",
    ]
    real_hosts = ["www.acme-corp.com", "api.stripe.com", "shop.bigbounty.io",
                  "a1b2c3.cloudfront.net", "portal.mybank-online.com"]
    for h in lab_hosts:
        expect(f"lab[{h}]", lab_detect.classify_host(h) is not None, str(lab_detect.classify_host(h)))
    for h in real_hosts:
        expect(f"real[{h}]", lab_detect.classify_host(h) is None, str(lab_detect.classify_host(h)))
    expect("dotted_ip_trick_blocked",
           lab_detect.is_lab({"cases": [{"url": "http://172.18.0.3.evil.com/"}]}) is True,
           "172.18.0.3.evil.com must be lab")
    expect("nested_request_url_seen",
           lab_detect.is_lab({"cases": [{"request": {"url": "http://10.10.10.5/x"}}]}) is True,
           "nested request.url must be inspected")
    expect("real_pack_not_lab",
           lab_detect.is_lab({"cases": [{"url": "https://portal.mybank-online.com/api"}]}) is False,
           "real host must not be lab")

    # retest_strict 也必须用同一套判定
    import retest_strict

    expect("retest_lab_htb", retest_strict.is_lab({"cases": [{"url": "http://10.10.10.5/api"}]}) is True, "")
    expect("retest_real_not_lab",
           retest_strict.is_lab({"cases": [{"url": "https://portal.mybank-online.com/api"}]}) is False, "")

    # ---------- 定级 ----------
    print("\n[C] 定级必须按证据形态，不按漏洞类型")
    from submit_brief import brief as _brief

    def ceil(kind: str, text: str) -> str:
        return _brief(lab=False, gate_ok=True, recommended="reproduced",
                      kind=kind, title=text, impact=text, claimed_severity="critical")["severity_ceiling"]

    cases_high = [
        ("info-disclosure", "source code disclosure via .git with production database password", "critical"),
        ("information-disclosure", "AWS access key validated with sts:GetCallerIdentity", "critical"),
        ("ssrf", "SSRF reaches 169.254.169.254 and returns IAM credentials", "critical"),
        ("auth-bypass", "JWT alg=none grants admin impersonation", "critical"),
    ]
    for kind, text, want in cases_high:
        expect(f"ceil_high[{kind}]", ceil(kind, text) == want, f"{ceil(kind, text)} != {want}")

    expect("ceil_s3_pii", ceil("info-disclosure", "S3 bucket exposes 2M user records with full PII") == "high",
           ceil("info-disclosure", "S3 bucket exposes 2M user records with full PII"))
    expect("ceil_idor_pii", ceil("idor", "any user can read any other user's PII") == "high",
           ceil("idor", "any user can read any other user's PII"))
    expect("ceil_stored_xss_admin", ceil("xss", "stored XSS in admin panel fires on every admin visit") == "high",
           ceil("xss", "stored XSS in admin panel fires on every admin visit"))
    expect("ceil_plain_listing_low", ceil("info-disclosure", "directory listing of /static assets") == "low",
           ceil("info-disclosure", "directory listing of /static assets"))
    expect("ceil_na_header", ceil("missing-header", "missing CSP header") == "do-not-submit",
           ceil("missing-header", "missing CSP header"))
    expect("ceil_na_selfxss", ceil("self-xss", "self-XSS in profile bio") == "do-not-submit",
           ceil("self-xss", "self-XSS in profile bio"))

    r = _brief(lab=True, gate_ok=True, recommended="reproduced", kind="idor",
               title="read other user PII", impact="read other user PII", claimed_severity="high")
    expect("lab_never_submit", r["submit_action"] == "do-not-submit", str(r["submit_action"]))
    expect("lab_ceiling_na", r["severity_ceiling"] == "do-not-submit", str(r["severity_ceiling"]))

    r = _brief(lab=False, gate_ok=True, recommended="reproduced", kind="info-disclosure",
               title="S3 bucket exposes 2M user records with full PII",
               impact="S3 bucket exposes 2M user records with full PII", claimed_severity="critical")
    expect("overclaim_flagged", r["claimed_too_high"] is True, str(r))
    expect("overclaim_needs_human", r["submit_action"] == "needs-human", str(r["submit_action"]))

    # ---------- scope ----------
    print("\n[D] scope_check 必须 fail closed")
    p = run(SCOPE + ["--task-id", "999999", "--url", "https://example.com/x", "--json"])
    sc = parse(p)
    expect("scope_empty_blocks", sc.get("verdict") == "out-of-scope", str(sc))
    expect("scope_empty_nonzero", p.returncode != 0, str(p.returncode))
    expect("scope_fail_closed", sc.get("fail_closed") is True, str(sc))
    p = run(SCOPE + ["--task-id", "999999", "--url", "", "--json"])
    sc = parse(p)
    expect("scope_no_host_blocks", sc.get("verdict") == "out-of-scope", str(sc))
    # 有 scope 的任务：内网地址应放行，公网应拦截
    p = run(SCOPE + ["--task-id", "6", "--url", "http://172.18.0.3:3000/api/Users", "--json"])
    sc = parse(p)
    if sc.get("scope_entries") is None and sc.get("verdict") in ("in-scope", "out-of-scope"):
        # 只有库可用时才有意义
        if sc.get("verdict") == "in-scope":
            expect("scope_task6_allows_ip", True, "")
            p2 = run(SCOPE + ["--task-id", "6", "--url", "https://example.com/x", "--json"])
            sc2 = parse(p2)
            expect("scope_task6_blocks_other", sc2.get("verdict") == "out-of-scope", str(sc2))
        else:
            print("  SKIP  scope task6 (DB scope not readable in this environment)")
    else:
        print("  SKIP  scope task6 (DB scope not readable in this environment)")
    # 后缀伪装必须拦住
    p = run(SCOPE + ["--task-id", "6", "--url", "http://172.18.0.3.evil.com/", "--json"])
    sc = parse(p)
    expect("scope_suffix_trick_blocked", sc.get("verdict") == "out-of-scope", str(sc))

    # ---------- coverage ----------
    print("\n[E] 覆盖台账必须拒绝空口声明")
    ledger = os.path.join(tmp, "coverage.json")
    p = run(COV_REC + ["--task-id", "424242", "--surface", "/api/Users", "--risk", "bfla",
                       "--outcome", "no_issue_found", "--evidence", "403 on admin op",
                       "--path", ledger, "--json"])
    expect("cov_record_ok", p.returncode == 0, p.stderr or p.stdout)
    p = run(COV_REC + ["--task-id", "424242", "--surface", "/x", "--risk", "idor",
                       "--outcome", "needs_follow_up", "--path", ledger, "--json"])
    expect("cov_followup_needs_note", p.returncode != 0, p.stdout + p.stderr)
    p = run(COV_REC + ["--task-id", "424242", "--surface", "/x", "--risk", "idor",
                       "--outcome", "probably_fine", "--path", ledger, "--json"])
    expect("cov_bad_outcome_rejected", p.returncode != 0, p.stdout + p.stderr)
    p = run(COV_REC + ["--task-id", "424242", "--surface", "", "--risk", "idor",
                       "--outcome", "reported", "--path", ledger, "--json"])
    expect("cov_empty_surface_rejected", p.returncode != 0, p.stdout + p.stderr)
    p = run(COV_REP + ["--task-id", "424242", "--ledger", os.path.join(tmp, "nope.json"),
                       "--assigned-risk", "idor", "--json"])
    cr = parse(p)
    expect("cov_empty_not_ok", cr.get("ok") is False, str(cr.get("problems")))
    expect("cov_empty_gap", any("idor" in g for g in (cr.get("gaps") or [])), str(cr.get("gaps")))
    p = run(COV_REC + ["--task-id", "424242", "--surface", "/x", "--risk", "idor",
                       "--outcome", "needs_follow_up", "--note", "suspicious, no PoC yet",
                       "--path", ledger, "--json"])
    expect("cov_followup_recorded", p.returncode == 0, p.stderr or p.stdout)
    p = run(COV_REP + ["--task-id", "424242", "--ledger", ledger, "--json"])
    cr = parse(p)
    expect("cov_open_item_blocks", cr.get("ok") is False, str(cr.get("problems")))
    expect("cov_open_item_listed", len(cr.get("open_items") or []) == 1, str(cr.get("open_items")))
    # 覆盖同一 surface+risk 应替换而非累加
    p = run(COV_REC + ["--task-id", "424242", "--surface", "/x", "--risk", "idor",
                       "--outcome", "ruled_out", "--evidence", "input type=uuid, DB lookup parameterized",
                       "--path", ledger, "--json"])
    expect("cov_ruled_out_ok", p.returncode == 0, p.stderr or p.stdout)
    doc = json.loads(open(ledger, encoding="utf-8").read())
    idor_rows = [r for r in doc["rows"] if r["surface"] == "/x" and r["risk"] == "idor"]
    expect("cov_replaces_same_key", len(idor_rows) == 1, str(idor_rows))
    expect("cov_replaced_outcome", idor_rows[0]["outcome"] == "ruled_out", str(idor_rows[0]))

    # ---------- F. 2026-10-19 独立审查发现的 3 个真实 bug（回归锁） ----------
    import report_check as rc
    import coverage_record as cr

    # F1 自评虚高：目录列表自评 Critical 必须被拦
    inflated = "/tmp/rc_inflated.md"
    with open(inflated, "w", encoding="utf-8") as f:
        f.write(
            "# T\n\n## Summary\nx\n\n## Counterevidence\n- 对照: 访问首页不含该文件；"
            "排除缓存；结论：目录列表暴露备份文件。\n\n## Confidence\n- 等级: high\n"
            "- 依据: gate ok\n\n## Severity Change Conditions\n- 升级条件: 含生产凭据\n"
            "- 降级条件: 文件本就公开\n\n## Evidence Binding\n- 证据包: /app/data/evidence/finding-7/\n\n"
            "## Severity (CVSS 3.1)\n- Score: 10.0 (Critical)\n"
        )
    r = rc.check(open(inflated, encoding="utf-8").read(), "7", "", "info-disclosure")
    expect("review_self_inflated_severity_blocked",
           any("高于证据可支撑的上限" in p for p in r["problems"]), str(r["problems"]))

    # F2 「Severity Change Conditions」不能被当成定级段
    sev_doc = (
        "## Severity Change Conditions\n- 升级条件: x\n\n"
        "## Severity (CVSS 3.1)\n- Score: 9.8 (Critical)\n"
    )
    expect("review_severity_section_not_shadowed",
           rc._reported_severity(sev_doc) == "critical", str(rc._reported_severity(sev_doc)))
    # Confidence 段里的「等级: high」不能被当成严重度
    conf_doc = "## Confidence\n- 等级: high\n\n## Severity (CVSS 3.1)\n- Score: 5.3 (Medium)\n"
    expect("review_confidence_not_read_as_severity",
           rc._reported_severity(conf_doc) == "medium", str(rc._reported_severity(conf_doc)))

    # F3 篡改 response.body 后，report_check 必须发现（verify_pack 本身发现不了）
    import shutil
    tam = "/tmp/review_tamper/finding-777"
    try:
        shutil.rmtree("/tmp/review_tamper")
    except Exception:
        pass
    shutil.copytree("/app/data/evidence/finding-7", tam)
    with open(os.path.join(tam, "cases/attack-ftp-listing/response.body"), "a") as f:
        f.write("\nTAMPERED\n")
    old_root = rc.EVIDENCE_ROOT
    rc.EVIDENCE_ROOT = "/tmp/review_tamper"
    ev = rc._load_evidence("777")
    rc.EVIDENCE_ROOT = old_root
    expect("review_tampered_body_detected",
           ev["case_sigs"].get("attack-ftp-listing", "").startswith("bad:"), str(ev["case_sigs"]))
    expect("review_pack_alone_misses_body_tamper", ev["pack_sig"] == "ok",
           "pack_sig 应为 ok —— 正说明必须额外跑 verify_case")

    # F4 台账路径与 cwd 无关
    p1 = cr.default_path(31337)
    old = os.getcwd()
    os.chdir("/tmp")
    p2 = cr.default_path(31337)
    os.chdir(old)
    expect("review_ledger_path_cwd_independent", p1 == p2 == "/app/data/tasks/31337/coverage.json", f"{p1} vs {p2}")

    # ---------- G. inet_aton 变体 IP（2026-10-19 第二次审查） ----------
    from lab_detect import is_lab_text as _lab, to_ip as _to_ip

    variants = {
        "http://0177.0.0.1/": "127.0.0.1",      # 八进制
        "http://0x7f.0.0.1/": "127.0.0.1",      # 十六进制
        "http://127.1/": "127.0.0.1",           # 缩写
        "http://127.0.1/": "127.0.0.1",
        "http://2130706433/": "127.0.0.1",      # 十进制整数
        "http://0x7f000001/": "127.0.0.1",      # 十六进制整数
        "http://017700000001/": "127.0.0.1",    # 八进制整数
        "http://0300.0250.0001.0001/": "192.168.1.1",
        "http://10.1/": "10.0.0.1",
        "http://0xa.0.0.1/": "10.0.0.1",
    }
    for u, want in variants.items():
        got = _to_ip(u.split("//", 1)[1].rstrip("/"))
        expect(f"variant_ip_parse[{u}]", str(got) == want, f"got={got} want={want}")
        expect(f"variant_ip_lab[{u}]", _lab(u), f"got={_lab(u)}")

    # 真实公网必须不被误判
    for u in ("http://8.8.8.8/", "https://1.1.1.1", "http://93.184.216.34/",
              "https://www.target.com", "https://api.hackerone.com"):
        expect(f"variant_ip_not_lab[{u}]", not _lab(u), f"got={_lab(u)}")

    # scope_check 必须与 lab_detect 用同一套 IP 语义
    for h, want in (("0xac.0x12.0.3", "in-scope"), ("2886860803", "in-scope"),
                    ("172.18.3", "in-scope"), ("0254.022.0.3", "in-scope"),
                    ("172.18.0.4", "out-of-scope"), ("8.8.8.8", "out-of-scope")):
        p = run(SCOPE + ["--task-id", "6", "--host", h, "--json"])
        v = json.loads(p.stdout)["verdict"] if p.stdout.strip() else "ERR"
        expect(f"scope_variant_ip[{h}]", v == want, f"got={v} want={want}")

    # ---------- H. SPA fallback 误判（2026-10-19 第三次审查，真实流量发现） ----------
    # 原逻辑用 url.endswith("/") 认首页，把 /ftp/、/admin/ 这类任何带尾斜杠的
    # 路径全当成首页 → 真实差异被误判成 SPA fallback 而拒收。
    import hashlib
    spa = "/tmp/reg_spa_false"
    try:
        shutil.rmtree(spa)
    except Exception:
        pass
    os.makedirs(spa + "/cases")
    b_attack = b"<html>Index of /ftp: package.json.bak</html>"
    b_home = b"<html>Welcome home</html>"
    for nm, body, url in (("attack-ftp", b_attack, "http://127.0.0.1:8899/ftp/"),
                          ("control-home", b_home, "http://127.0.0.1:8899/")):
        d = os.path.join(spa, "cases", nm)
        os.makedirs(d)
        open(os.path.join(d, "response.body"), "wb").write(body)
    with open(os.path.join(spa, "pack.json"), "w") as f:
        json.dump({"cases": [
            {"name": "attack-ftp", "url": "http://127.0.0.1:8899/ftp/",
             "body_sha256": hashlib.sha256(b_attack).hexdigest(), "body_len": len(b_attack),
             "checks_pass": True},
            {"name": "control-home", "url": "http://127.0.0.1:8899/",
             "body_sha256": hashlib.sha256(b_home).hexdigest(), "body_len": len(b_home),
             "checks_pass": True}],
            "compares": [{"attack": "attack-ftp", "control": "control-home", "pass": True}]},
            f)
    p = run(["python3", f"{ROOT}/evidence_gate.py", spa])
    txt = p.stdout
    expect("review_trailing_slash_not_homepage",
           "SPA fallback" not in txt,
           "尾斜杠路径 /ftp/ 不应被当成首页（否则真实差异被误判为 SPA）")


    # ---------- I. 路径归一化与一级泛化容器（2026-10-19 第四次审查） ----------
    from submit_brief import path_prefixes as _pp, lookup_task_duplicates as _lookup
    # 各种变形必须归一化到同一组前缀
    for p in ("/ftp", "/ftp/", "/FTP", "/ftp?x=1", "/ftp#f", "/./ftp", "//ftp",
              "/f%74p", "ftp", "http://h:3000/ftp?q=1"):
        pre = _pp(p)
        expect(f"pathnorm[{p}]", "/ftp" in pre, f"got={pre}")
    # 一级泛化容器不应把不同资源串成重复（/rest vs /rest/user/login）
    rows = [{"id": 1, "vulnclass": "info-disclosure", "severity": "medium",
             "summary": "POST /rest/user/login 签发 JWT", "name": ""}]
    hits = _lookup("", "info-disclosure", [], ["/rest/products"], _rows=rows)
    expect("generic_container_no_false_dup", hits == [], f"got={hits}")
    hits2 = _lookup("", "info-disclosure", [], ["/rest/user/login"], _rows=rows)
    expect("specific_path_still_matches", len(hits2) == 1, f"got={hits2}")

    # ---------- J. coverage_report 逐条对账（2026-10-19 第五次审查） ----------
    # 原逻辑：只要有一条 outcome=reported 且 vulnclass 相同，就把该类型
    # 所有 finding 认成「已覆盖」。实测 task 6 里一条 /ftp 的 reported
    # 把 #8(/encryptionkeys)、#9(JWT MD5) 全部掩盖 —— 12 条未登记只报出 12 条
    # 之前甚至把 #7/#8/#9/#10 全放过。必须逐条按资源对账。
    import coverage_report as _cr
    _f_ftp = {"finding_id": 7, "vulnclass": "info-disclosure", "name": "",
              "summary": "Unauthenticated /ftp directory listing exposes docs"}
    _f_enc = {"finding_id": 8, "vulnclass": "info-disclosure", "name": "",
              "summary": "Unauthenticated /encryptionkeys directory listing exposes jwt.pub"}
    expect("cr_same_resource_matches",
           _cr._surface_overlaps("/ftp", _f_ftp) is True,
           "同一资源 /ftp 应判定为覆盖")
    expect("cr_diff_resource_not_matched",
           _cr._surface_overlaps("/ftp", _f_enc) is False,
           "不同资源 /encryptionkeys 不能被 /ftp 那行掩盖")
    expect("cr_enc_matches_own",
           _cr._surface_overlaps("/encryptionkeys", _f_enc) is True,
           "/encryptionkeys 应命中自己的 finding")
    expect("cr_root_surface_never_matches",
           _cr._surface_overlaps("/", _f_ftp) is False,
           "根路径台账行不能代表任意 finding")
    expect("cr_no_path_in_text",
           _cr._surface_overlaps("/ftp", {"finding_id": 99, "vulnclass": "xss",
                                          "name": "", "summary": "no path here"}) is False,
           "文本里没有路径时不得认成覆盖")

    print(f"\n=== {PASS} passed, {FAIL} failed ===")
    for e in ERRORS:
        print(" -", e)
    out = "/app/data/sessions/conv-85/gates-hardening-results.json"
    try:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"pass": PASS, "fail": FAIL, "errors": ERRORS}, f, ensure_ascii=False, indent=2)
        print(f"results -> {out}")
    except Exception as e:
        print(f"warn: cannot write results: {e}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
