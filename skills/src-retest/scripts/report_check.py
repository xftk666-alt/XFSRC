#!/usr/bin/env python3
"""提交稿机械校验：四段强制 + 证据绑定 + 判重 + 定级天花板。

为什么需要它：
  src-report-writing 里的四段（Counterevidence / Confidence /
  Severity Change Conditions / Evidence Binding）如果只是文本要求，
  agent 完全可以不写。这个脚本把它们变成**可检查的失败项**。

用法：
  python3 report_check.py --report draft.md --finding-id 7 --task-id 6
  python3 report_check.py --report draft.md --finding-id 7 --task-id 6 --json

退出码：
  0  通过
  1  有阻塞问题（不可提交）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_ROOT = "/app/data/evidence"

REQUIRED_SECTIONS = {
    "counterevidence": r"^#{1,6}\s*.*counterevidence|^#{1,6}\s*.*反证",
    "confidence": r"^#{1,6}\s*.*confidence|^#{1,6}\s*.*置信度",
    "severity_change": r"^#{1,6}\s*.*severity\s*change|^#{1,6}\s*.*降级条件|^#{1,6}\s*.*升级条件",
    "evidence_binding": r"^#{1,6}\s*.*evidence\s*binding|^#{1,6}\s*.*证据绑定",
}


def _section(text: str, name: str) -> str:
    """取某个标题下的正文（到下一个同级或更高级标题为止）。"""
    pat = REQUIRED_SECTIONS[name]
    lines = text.splitlines()
    start = None
    level = 0
    for i, ln in enumerate(lines):
        m = re.match(r"^(#{1,6})\s", ln)
        if m and re.search(pat, ln, re.I):
            start = i
            level = len(m.group(1))
            break
    if start is None:
        return ""
    body = []
    for ln in lines[start + 1:]:
        m = re.match(r"^(#{1,6})\s", ln)
        if m and len(m.group(1)) <= level:
            break
        body.append(ln)
    return "\n".join(body).strip()


def _reported_severity(report: str) -> str | None:
    """从报告的 Severity 段取自评严重度。

    必须限定在 Severity / 定级 段内：Confidence 段也有「等级: high」，
    全局正则会把置信度误当成严重度（实测踩过）。
    """
    lines = report.splitlines()
    start = level = None
    for i, ln in enumerate(lines):
        m = re.match(r"^(#{1,6})\s", ln)
        if not m:
            continue
        # 「Severity Change Conditions」是四段之一，不是定级段，必须排除
        if re.search(r"severity\s*change|降级条件|升级条件", ln, re.I):
            continue
        if re.search(r"severity|定级|严重度|CVSS", ln, re.I):
            start, level = i, len(m.group(1))
            break
    body = ""
    if start is not None:
        buf = []
        for ln in lines[start + 1:]:
            m = re.match(r"^(#{1,6})\s", ln)
            if m and len(m.group(1)) <= level:
                break
            buf.append(ln)
        body = "\n".join(buf)

    scope = body or report
    m = re.search(r"Score\s*[:：]?\s*[0-9.]+\s*\(?\s*(critical|high|medium|low)\b", scope, re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"(?im)^\s*[-*]?\s*(?:severity|严重度|等级|rating)\s*[:：]\s*(critical|high|medium|low)\b", scope)
    if m:
        return m.group(1).lower()
    m = re.search(r"\((critical|high|medium|low)\)", scope, re.I)
    if m:
        return m.group(1).lower()
    return None


def _load_evidence(finding_id: str, outdir: str = "") -> dict:
    """定位证据包。

    outdir 优先：证据包不一定叫 finding-<id>（复测会话、临时包、
    独立复现都可能用别的目录名）。写死 finding-<id> 会让校验器
    对合法证据包报「不存在」，从而被绕过或误拦（实测踩过）。
    """
    d = os.path.abspath(outdir) if outdir else os.path.join(EVIDENCE_ROOT, f"finding-{finding_id}")
    out = {"dir": d, "exists": os.path.isdir(d), "pack": None, "seal": False,
           "gate_ok": False, "gate_sig": None, "verdict": None, "verdict_sig": None,
           "submit_advice": None, "lab": None, "sha256s": set(), "cases": []}
    if not out["exists"]:
        return out
    p = os.path.join(d, "pack.json")
    if os.path.isfile(p):
        try:
            out["pack"] = json.load(open(p))
        except Exception:
            out["pack"] = None
    out["seal"] = os.path.isfile(os.path.join(d, "pack.seal.json"))
    # pack 用的是 pack_canonical（与 gate/verdict 的 verify_document 不同），必须走 verify_pack
    out["pack_sig"] = "unverified"
    out["case_sigs"] = {}
    try:
        sys.path.insert(0, _HERE)
        from evidence_seal import verify_pack, verify_document, verify_case
        if out["seal"]:
            ok, why = verify_pack(d)
            out["pack_sig"] = "ok" if ok else f"bad:{why}"
        # verify_pack 只看 pack.json；response.body 由 verify_case 单独校验。
        # 少了这一步，篡改 response.body 后 pack 仍然 ok（实测踩过）。
        for name in (out["pack"] or {}).get("cases", []):
            cname = name.get("name") if isinstance(name, dict) else None
            if not cname:
                continue
            cdir = os.path.join(d, "cases", cname)
            if not os.path.isdir(cdir):
                out["case_sigs"][cname] = "missing"
                continue
            cok, cwhy = verify_case(cdir)
            out["case_sigs"][cname] = "ok" if cok else f"bad:{cwhy}"
    except Exception as e:
        out["pack_sig"] = f"unverifiable:{e.__class__.__name__}"

    # gate.json / verdict.json 是带 HMAC 的信封：真正字段在 payload 里
    for name, key in (("gate.json", "gate"), ("verdict.json", "verdict")):
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            continue
        try:
            doc = json.load(open(path))
        except Exception:
            continue
        payload = doc.get("payload") or {}
        sig = "unsigned"
        try:
            sys.path.insert(0, _HERE)
            from evidence_seal import verify_document
            ok, why = verify_document(doc)
            sig = "ok" if ok else f"bad:{why}"
        except Exception as e:
            sig = f"unverifiable:{e.__class__.__name__}"
        if key == "gate":
            out["gate_ok"] = bool(payload.get("ok"))
            out["gate_sig"] = sig
            out["submit_advice"] = payload.get("submit_advice")
            out["lab"] = payload.get("lab")
        else:
            out["verdict"] = payload.get("verdict")
            out["verdict_sig"] = sig
            out["submit_advice"] = out["submit_advice"] or payload.get("submit_advice")
            if out["lab"] is None:
                out["lab"] = payload.get("lab")

    for c in (out["pack"] or {}).get("cases", []):
        out["cases"].append(c.get("name"))
        if c.get("body_sha256"):
            out["sha256s"].add(str(c["body_sha256"]).lower())
    return out


def check(report: str, finding_id: str, task_id: str, kind: str = "",
          host: list[str] | None = None, path: list[str] | None = None,
          outdir: str = "") -> dict:
    problems: list[str] = []
    warnings: list[str] = []

    # 1) 四段存在性
    bodies = {}
    for name in REQUIRED_SECTIONS:
        b = _section(report, name)
        bodies[name] = b
        if not b:
            problems.append(f"缺少强制段落：{name}（见 src-report-writing 3.2）")

    # 2) 反证不能是空话
    ce = bodies.get("counterevidence", "")
    if ce and not re.search(r"对照|control|换|去掉|排除|对比", ce, re.I):
        problems.append("Counterevidence 里没有可识别的对照实验（只写「我复现了」不算反证）")
    if ce and len(ce) < 30:
        problems.append("Counterevidence 过短，看不出排除了哪种替代解释")

    # 3) 置信度
    cf = bodies.get("confidence", "")
    m = re.search(r"\b(high|medium|low)\b", cf, re.I)
    if cf and not m:
        problems.append("Confidence 未给出 high/medium/low")
    elif m and m.group(1).lower() == "low":
        problems.append("Confidence=low 的报告不应提交")

    # 4) 降级/升级条件
    sc = bodies.get("severity_change", "")
    if sc and not re.search(r"升级|降级|escalat|downgrad|会变|提高到|压到", sc, re.I):
        problems.append("Severity Change Conditions 没写清什么证据会改分")

    # 5) 证据绑定
    ev = _load_evidence(finding_id, outdir)
    if not ev["exists"]:
        problems.append(f"证据包不存在：{ev['dir']}")
    else:
        if not ev["seal"]:
            problems.append("证据包缺少 HMAC pack.seal.json")
        elif ev.get("pack_sig") != "ok":
            problems.append(f"pack.seal.json 校验未通过（{ev.get('pack_sig')}）")
        bad_cases = {k: v for k, v in (ev.get("case_sigs") or {}).items() if v != "ok"}
        if bad_cases:
            problems.append(f"{len(bad_cases)} 个 case 的正文/请求被篡改或缺失：{list(bad_cases)[:3]}")
        if not ev["gate_ok"]:
            problems.append("gate.json 不存在或 payload.ok != true")
        elif ev["gate_sig"] != "ok":
            problems.append(f"gate.json 的 HMAC 校验未通过（{ev['gate_sig']}）")
        if ev["verdict"] != "reproduced":
            problems.append(f"verdict 不是 reproduced（当前 {ev['verdict']}）")
        elif ev["verdict_sig"] != "ok":
            problems.append(f"verdict.json 的 HMAC 校验未通过（{ev['verdict_sig']}）")
        if ev.get("submit_advice") == "never":
            problems.append(f"证据包的 submit_advice=never（{ev.get('lab') and '靶场/CTF' or '不可提交'}）")
        eb = bodies.get("evidence_binding", "")
        if eb:
            cited = {s.lower() for s in re.findall(r"\b[0-9a-f]{64}\b", eb, re.I)}
            unknown = cited - ev["sha256s"]
            if unknown:
                problems.append(f"Evidence Binding 里 {len(unknown)} 个 sha256 在 pack.json 中找不到（疑似编造）")
            if ev["sha256s"] and not cited:
                warnings.append("Evidence Binding 没有引用任何 sha256，无法机器核对")

    # 6) 定级天花板：报告自评不能超过证据能支撑的档
    #    （原 docstring 声称有这一项但代码没实现，等于「自评虚高」完全裸奔）
    sev = _reported_severity(report)
    if sev:
        try:
            sys.path.insert(0, _HERE)
            from submit_brief import submit_ceiling
            cap = submit_ceiling(kind or "", report, False)
            order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            if cap in order and sev in order and order[sev] > order[cap]:
                problems.append(
                    f"自评 {sev} 高于证据可支撑的上限 {cap}（按 src-report-writing 3.1 改分或补证据）")
        except Exception as e:
            warnings.append(f"定级天花板未能校验：{e.__class__.__name__}")

    # 7) 判重
    if task_id and kind:
        argv = ["python3", os.path.join(_HERE, "dup_check.py"), "--task-id", str(task_id), "--kind", kind]
        for h in (host or []):
            argv += ["--host", h]
        for p in (path or []):
            argv += ["--path", p]
        r = subprocess.run(argv, capture_output=True, text=True)
        if r.returncode == 3:
            problems.append("dup_check 发现重复候选：先按 src-triage 判重五问处理")

    # 7) 靶场
    try:
        sys.path.insert(0, _HERE)
        from lab_detect import is_lab as _is_lab
        if ev["pack"] and _is_lab(ev["pack"]):
            problems.append("证据包指向靶场/非真实资产，不可提交到三家")
    except Exception:
        pass

    return {"ok": not problems, "problems": problems, "warnings": warnings,
            "finding_id": finding_id, "evidence_dir": ev["dir"],
            "cases": ev["cases"], "sections_found": [k for k, v in bodies.items() if v]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="提交稿机械校验（四段强制 + 证据绑定）")
    ap.add_argument("--report", required=True)
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--outdir", default="", help="证据包目录（默认 /app/data/evidence/finding-<id>）")
    ap.add_argument("--task-id", default="")
    ap.add_argument("--kind", default="")
    ap.add_argument("--host", action="append", default=[])
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    report = open(a.report, encoding="utf-8").read()
    r = check(report, a.finding_id, a.task_id, a.kind, a.host, a.path, a.outdir)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        if r["ok"]:
            print("[OK] 四段齐全、证据绑定可核对、无重复候选")
        else:
            print("[BLOCKED] 不可提交：")
            for p in r["problems"]:
                print(f"  - {p}")
        for w in r["warnings"]:
            print(f"  [warn] {w}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
