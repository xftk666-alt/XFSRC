#!/usr/bin/env python3
"""taxonomy_gap.py — 把 taxonomy.csv（应测什么）与 coverage.json（实测什么）交叉，算出缺口。

用法:
  python3 taxonomy_gap.py --task-id 6
  python3 taxonomy_gap.py --task-id 6 --family 14 --json
  python3 taxonomy_gap.py --task-id 6 --only-uncovered

退出码:
  0 无未覆盖项（或有记录覆盖）
  1 存在未覆盖的 covered 类（宣布 clean 前必须处理）
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TAXONOMY = os.path.join(os.path.dirname(HERE), "taxonomy.csv")
if not os.path.isfile(TAXONOMY):
    TAXONOMY = "/app/skills/src-taxonomy/taxonomy.csv"

# 族编号 -> coverage risk 关键词（用于把台账 row.risk 映射到 taxonomy 族）
FAMILY_RISK_HINTS = {
    "1": ["info-disclosure", "info_disclosure", "secret", "source-map", "debug"],
    "2": ["request-smuggling", "cache-poisoning", "cache-deception", "desync"],
    "3": ["graphql", "api"],
    "4": ["takeover", "subdomain", "dns", "cloud", "infra"],
    "5": ["oauth", "saml", "sso", "oidc"],
    "6": ["ai", "llm", "prompt"],
    "7": ["supply-chain", "ci-cd", "dependency"],
    "8": ["crypto", "token", "jwt"],
    "9": ["ssrf"],
    "10": ["injection", "sqli", "ssti", "command-injection", "nosqli", "ldap"],
    "11": ["deserialization", "xxe", "xml", "parser"],
    "12": ["business-logic", "race", "workflow"],
    "13": ["auth", "session", "mfa", "password-reset"],
    "14": ["idor", "bfla", "bola", "authz", "access-control", "mass-assignment"],
    "15": ["file-upload", "path-traversal", "file-inclusion"],
    "16": ["xss", "client-side-injection", "dom-xss"],
    "17": ["cors", "cross-origin", "csrf", "clickjacking"],
    "18": ["open-redirect", "client-side-path"],
    "19": ["host-header", "redirect", "spoofing"],
    "20": ["dos", "resource-abuse", "rate-limit"],
    "21": ["adjacent", "subdomain"],
    "22": ["frontier"],
    "23": ["chain", "escalation"],
    "24": ["informational"],
}


def load_taxonomy(family: str = "") -> list[dict]:
    with open(TAXONOMY, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if family:
        rows = [r for r in rows if r["family"].startswith(family)]
    return rows


def load_coverage(task_id: str, path: str = "") -> dict:
    p = path or f"/app/data/tasks/{task_id}/coverage.json"
    if not os.path.isfile(p):
        alt = os.path.join(os.getcwd(), f"coverage-task{task_id}.json")
        p = alt if os.path.isfile(alt) else p
    if not os.path.isfile(p):
        return {"rows": [], "path": p, "exists": False}
    try:
        return json.load(open(p, encoding="utf-8")) | {"path": p, "exists": True}
    except Exception:
        return {"rows": [], "path": p, "exists": False}


def family_of_row(row: dict) -> str:
    """把 coverage 的 risk 反推回族编号。"""
    risk = str(row.get("risk", "")).lower()
    for fam, hints in FAMILY_RISK_HINTS.items():
        if any(h in risk for h in hints):
            return fam
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--path", default="", help="coverage.json 路径")
    ap.add_argument("--family", default="", help="只看某族，如 14")
    ap.add_argument("--only-uncovered", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    tax = load_taxonomy(a.family)
    cov = load_coverage(a.task_id, a.path)
    covered_fams = {}
    for row in cov.get("rows", []):
        fam = family_of_row(row)
        if not fam:
            continue
        covered_fams.setdefault(fam, set()).add(str(row.get("outcome", "")))

    families = sorted({r["family"] for r in tax}, key=lambda s: int(s.split(".")[0]))
    report = {"task_id": a.task_id, "coverage_path": cov["path"], "coverage_exists": cov["exists"], "families": []}
    total_uncovered = 0
    total_uncovered_all = 0

    for fam in families:
        num = fam.split(".")[0]
        classes = [r for r in tax if r["family"] == fam]
        outcomes = covered_fams.get(num, set())
        # 族级判定：台账里该族有任一 outcome 即视为"有记录"
        if not outcomes:
            status = "untouched"
        elif "needs_follow_up" in outcomes:
            status = "follow_up"
        elif outcomes & {"reported", "no_issue_found", "ruled_out", "not_applicable"}:
            status = "recorded"
        else:
            status = "untouched"

        actionable = [r for r in classes if r["decision"] in ("covered", "partial")]
        uncovered = actionable if status == "untouched" else []
        total_uncovered_all += len(uncovered)
        if not (a.only_uncovered and status != "untouched"):
            total_uncovered += len(uncovered)

        entry = {
            "family": fam,
            "classes_total": len(classes),
            "actionable": len(actionable),
            "status": status,
            "outcomes": sorted(outcomes),
            "uncovered_classes": [r["vuln_class"] for r in uncovered],
            "top_p1": [
                f"{r['priority']} {r['payout']} {r['vuln_class']}"
                for r in actionable
                if r["priority"].startswith("P1")
            ][:8],
            "backlog": [r["vuln_class"] for r in classes if r["decision"] == "backlog"][:6],
        }
        if a.only_uncovered and status != "untouched":
            continue
        report["families"].append(entry)

    report["uncovered_actionable_classes"] = total_uncovered
    report["uncovered_actionable_classes_all"] = total_uncovered_all

    if a.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"task {a.task_id}  taxonomy={TAXONOMY}")
        print(f"coverage={cov['path']} (exists={cov['exists']})")
        print(f"未触碰的族: {sum(1 for f in report['families'] if f['status']=='untouched')} / {len(report['families'])}")
        print(f"未覆盖的可测类: {total_uncovered}" + (f" (全量 {total_uncovered_all})" if a.only_uncovered else ""))
        print()
        for f in report["families"]:
            mark = {"recorded": "OK ", "follow_up": "F/U", "untouched": "GAP"}[f["status"]]
            print(f"[{mark}] {f['family']}  ({f['actionable']}/{f['classes_total']} 可测)")
            if f["status"] == "untouched" and f["top_p1"]:
                for t in f["top_p1"][:4]:
                    print(f"        P1: {t}")
            if f["backlog"]:
                print(f"        backlog: {', '.join(f['backlog'][:3])}")
    return 1 if total_uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
