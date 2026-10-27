#!/usr/bin/env python3
"""SKILL.md 结构 / 合规 / 反误报纪律校验器。

用途：新增或修改 src-* 技能后，跑一遍确认它没有退化。
它不是"渗透工具"，只读文件、不发网络请求。

检查项：
  1. YAML frontmatter 存在，含 name / description
  2. name 与目录名一致，且符合小写字母/数字/连字符
  3. description 非空、足够长（>40 字符）、说明"何时用"
  4. 正文非空，且有明确标题
  5. 合规红线：必须出现授权/scope 相关约束
  6. 反误报纪律：必须出现"确认判据"或"误报"章节
  7. 禁止出现绕过安全闸门的表述（弱化 scope_check / dup_check /
     coverage_* / report_check / lab_detect）
  8. 禁止出现"代用户提交"类表述

用法：
  python3 skill_lint.py /app/skills/src-cors
  python3 skill_lint.py /app/skills            # 校验全部 src-*
  python3 skill_lint.py --json /app/skills
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# 合规红线关键词：至少命中一个（用词边界，避免 noscope 之类的子串误判）
SCOPE_PATTERNS = (
    r"授权",
    r"\bin-scope\b",
    r"\bout-of-scope\b",
    r"\bprogram\b",
    r"\bpolicy\b",
    r"\btask_scope\b",
    r"scope\s*(范围|内|外|检查|闸门)",
    r"(范围|授权范围)\s*(检查|闸门|内|外)",
    r"\bscope_check\b",
)

# 反误报纪律关键词：至少命中一个
ANTI_FP_WORDS = (
    "误报", "确认判据", "不算证据", "不算洞", "false positive",
    "排除", "对照", "算洞的证据", "不是洞", "成功证据",
)

# 明确禁止的弱化闸门表述
FORBIDDEN_PATTERNS = (
    (r"(跳过|绕过|关闭|禁用|不调用|弱化).{0,12}(scope_check|scope 检查|范围检查)", "弱化范围闸门"),
    (r"(跳过|绕过|关闭|禁用|不调用).{0,12}dup_check", "弱化查重闸门"),
    (r"(跳过|绕过|关闭|禁用|不调用|伪造).{0,12}(coverage_record|coverage_report)", "弱化覆盖台账"),
    (r"(跳过|绕过|关闭|禁用|不调用|伪造).{0,12}report_check", "弱化报告校验"),
    (r"(跳过|绕过|关闭|禁用).{0,12}lab_detect", "弱化靶场检测"),
    (r"直接(登记|写入).{0,6}finding.{0,12}(不|无需).{0,6}(校验|证据)", "无证据直接登记"),
    (r"(代|帮).{0,4}用户.{0,6}(提交|点提交|登录)", "代用户提交"),
    (r"(忽略|无视).{0,6}(scope|授权范围)", "无视授权范围"),
)


def parse_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    block = text[3:end].strip("\n")
    body = text[end + 4:]
    meta: dict[str, str] = {}
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", line)
        if m:
            meta[m.group(1)] = m.group(2).strip().strip("'\"")
    return meta, body


def classify(body: str, name: str) -> str:
    """判定技能类型，决定哪些检查项适用。

    test       = 会主动发请求的测试类技能（必须写 scope + 误报排除）
    discipline = 纪律/流程/编排类（不发请求，只约束行为）
    tool       = 通用工具使用说明（浏览器自动化/MCP 客户端等），不套渗透纪律
    """
    if name in ("playwright-cli", "scopesentry", "api-recon"):
        return "tool"
    request_markers = (
        "curl ", "curl\\", "browser_", "http_evidence", "oob_gen",
        "ffuf", "nuclei", "katana", "httpx", "请求", "发包",
    )
    discipline_markers = (
        "台账", "纪律", "编排", "门禁", "入口", "流程", "复测入口",
    )
    has_req = any(m in body for m in request_markers)
    has_disc = any(m in body for m in discipline_markers)
    if has_req and not has_disc:
        return "test"
    if has_disc and not has_req:
        return "discipline"
    # 两者都有：纪律类技能常引用请求示例，按纪律类处理更准确
    if name in ("src-coverage", "src-closure", "src-triage",
                "src-retest", "src-retest-dispatch", "src-hunter-brief"):
        return "discipline"
    return "test"


def lint_skill(skill_dir: str, profile: str = "auto") -> dict:
    name_dir = os.path.basename(os.path.normpath(skill_dir))
    path = os.path.join(skill_dir, "SKILL.md")
    problems: list[str] = []
    warnings: list[str] = []

    if not os.path.isfile(path):
        return {"skill": name_dir, "ok": False, "problems": ["SKILL.md 不存在"], "warnings": []}

    with open(path, encoding="utf-8") as f:
        text = f.read()

    meta, body = parse_frontmatter(text)
    kind = classify(body, name_dir) if profile == "auto" else profile

    if not meta:
        problems.append("缺少 YAML frontmatter")
    name = meta.get("name", "")
    desc = meta.get("description", "")

    if not name:
        problems.append("frontmatter 缺 name")
    else:
        if not NAME_RE.match(name):
            problems.append(f"name 不合法: {name!r}（只允许小写字母/数字/连字符）")
        if name != name_dir:
            problems.append(f"name({name}) 与目录名({name_dir}) 不一致")

    if not desc:
        problems.append("frontmatter 缺 description")
    elif len(desc) < 40:
        problems.append(f"description 过短({len(desc)} 字符)，应说明做什么/何时用")
    elif not re.search(r"(当|用于|when|use when)", desc, re.I):
        warnings.append("description 未说明'何时用'")

    if len(body.strip()) < 200:
        problems.append(f"正文过短({len(body.strip())} 字符)")

    if not re.search(r"^#\s+", body, re.M):
        problems.append("正文缺少一级标题")

    # 主动测试类才强制要求合规红线 + 反误报章节
    if kind == "test":
        if not any(re.search(p, body, re.I) for p in SCOPE_PATTERNS):
            problems.append("正文未提及授权/scope/program/policy —— 缺合规红线")
        if not any(w in body for w in ANTI_FP_WORDS):
            problems.append("正文未包含确认判据/误报排除章节")
    elif kind == "discipline":
        # 纪律类至少要能看出它在约束什么
        if not re.search(r"(必须|禁止|不许|不得|只能)", body):
            problems.append("纪律类技能未出现强制性约束措辞")
    # tool 类只做结构检查

    # 禁止的弱化表述（所有类型都查）
    for pat, label in FORBIDDEN_PATTERNS:
        if re.search(pat, body, re.I):
            problems.append(f"出现禁止表述（{label}）：匹配 /{pat}/")

    # 高危类目必须有"停"的约束
    high_risk = ("smuggling", "cache", "deserial", "rce", "upload")
    if any(k in name_dir for k in high_risk):
        if not re.search(r"(立即停|命中即停|不得|禁止|≤\s*\d+\s*个请求)", body):
            warnings.append("高危类目未写明请求上限或'命中即停'")

    return {
        "skill": name_dir,
        "kind": kind,
        "ok": not problems,
        "problems": problems,
        "warnings": warnings,
        "bytes": len(text.encode("utf-8")),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SKILL.md 结构与合规校验")
    ap.add_argument("target", help="单个技能目录，或包含多个技能的父目录")
    ap.add_argument("--profile", choices=["auto", "test", "discipline"], default="auto",
                    help="auto=按内容自动判定；test=强制按测试类校验；discipline=纪律类")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    target = a.target
    if os.path.isfile(os.path.join(target, "SKILL.md")):
        dirs = [target]
    elif os.path.isdir(target):
        dirs = [
            os.path.join(target, d)
            for d in sorted(os.listdir(target))
            if os.path.isfile(os.path.join(target, d, "SKILL.md"))
        ]
    else:
        print(f"[error] 路径不存在: {target}", file=sys.stderr)
        return 2

    results = [lint_skill(d, a.profile) for d in dirs]
    bad = [r for r in results if not r["ok"]]

    if a.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["ok"] else "FAIL"
            print(f"  {mark}  {r['skill']:<28} {r.get('kind',''):<10} {r.get('bytes', 0):>6}B")
            for p in r["problems"]:
                print(f"          ✗ {p}")
            for w in r["warnings"]:
                print(f"          ! {w}")
        print(f"\n=== {len(results) - len(bad)} passed, {len(bad)} failed "
              f"(共 {len(results)}) ===")

    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
