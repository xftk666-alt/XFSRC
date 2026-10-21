#!/usr/bin/env python3
"""覆盖台账体检：把「已上报的 finding」与「台账记录」对照，找三类问题。

1. 未记账的 finding —— 已 report_finding，但台账里没有对应行（说明台账没维护）
2. 空口覆盖 —— 台账写 reported，但该任务根本没有对应 vulnclass 的 finding
3. 缺口 —— 被分配了某类风险，但台账一行都没有（= 没测）
4. 未结项 —— needs_follow_up 未关闭（不许静默丢弃）

退出码：0 = 无缺口无未结项；1 = 有问题（可当 CI/完成门禁用）。

用法：
  python3 coverage_report.py --task-id 6 --assigned-risk idor --assigned-risk xss
  python3 coverage_report.py --task-id 6 --ledger /path/coverage.json --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from coverage_record import default_path, load, summary  # noqa: E402


class FindingsUnavailable(RuntimeError):
    """读不到 findings 表。

    「读不到」与「一条都没有」必须区分：旧实现两者都返回 []，于是数据库故障时
    覆盖体检得出「健康」结论（fail-open），未记账的 finding 全部被漏掉。
    """


def load_findings(task_id: int, dsn: str | None = None) -> list[dict[str, Any]]:
    dsn = dsn or os.environ.get("ARTEX_PG_DSN")
    if not dsn:
        raise FindingsUnavailable("未配置 ARTEX_PG_DSN")
    try:
        import psycopg2  # type: ignore
    except Exception as e:
        raise FindingsUnavailable(f"psycopg2 不可用（{e.__class__.__name__}）") from e
    try:
        conn = psycopg2.connect(dsn)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, vulnclass, severity, left(coalesce(name,''),120), left(coalesce(summary,''),240) "
            "FROM findings WHERE task_id = %s ORDER BY id",
            (int(task_id),),
        )
        rows = [
            {"finding_id": r[0], "vulnclass": (r[1] or "").lower(), "severity": r[2],
             "name": r[3] or "", "summary": r[4] or ""}
            for r in cur.fetchall()
        ]
        cur.close()
        conn.close()
        return rows
    except Exception as e:
        raise FindingsUnavailable(f"查询 findings 失败（{e.__class__.__name__}: {e}）") from e


def _risk_matches(ledger_risk: str, vulnclass: str) -> bool:
    a = (ledger_risk or "").lower().replace("-", "_")
    b = (vulnclass or "").lower().replace("-", "_")
    if not a or not b:
        return False
    return a == b or a in b or b in a


_PATH_RE = None


def _paths_in(text: str) -> set[str]:
    """从自由文本里抽路径。findings 表没有 URL 列，只有 name/summary，
    所以只能靠文本里的 /a/b 形态来判定「这条台账是不是在讲同一个资源」。"""
    global _PATH_RE
    import re
    if _PATH_RE is None:
        _PATH_RE = re.compile(r"/[A-Za-z0-9_\-{}.]+(?:/[A-Za-z0-9_\-{}.]+)*")
    out: set[str] = set()
    for m in _PATH_RE.findall(text or ""):
        p = m.rstrip(".,;:)").lower()
        # 太短的一律不算（"/"、"/x" 这种容易误配）
        if len([s for s in p.split("/") if s]) >= 1 and len(p) > 3:
            out.add(p)
    return out


def _surface_overlaps(surface: str, finding: dict[str, Any]) -> bool:
    """台账行 surface 与该 finding 文本是否指向同一资源。
    这是「一条 reported 行能否代表这条 finding」的唯一依据 —— 不能只看 vulnclass。
    """
    sp = (surface or "").strip().lower()
    if not sp or sp in ("/", "*"):
        return False
    # 规范化台账 surface：允许 /ftp、/ftp/、/rest/user/login
    sp_segs = [s for s in sp.split("/") if s]
    if not sp_segs:
        return False
    text = f"{finding.get('name') or ''} {finding.get('summary') or ''}".lower()
    for p in _paths_in(text):
        p_segs = [s for s in p.split("/") if s]
        # 段级前缀重叠：/ftp 命中 /ftp/…，/rest 不命中 /rest/user/login（避免 BUG-8 那类误判）
        n = min(len(sp_segs), len(p_segs))
        if n >= 1 and sp_segs[:n] == p_segs[:n]:
            return True
    return False


def report(
    task_id: int,
    ledger_path: str = "",
    assigned_risks: list[str] | None = None,
    dsn: str | None = None,
) -> dict[str, Any]:
    path = ledger_path or default_path(task_id)
    doc = load(task_id, path)
    rows = doc.get("rows", [])
    s = summary(task_id, path, assigned_risks)

    problems: list[str] = []
    findings_error = ""
    try:
        findings = load_findings(task_id, dsn)
    except FindingsUnavailable as e:
        findings, findings_error = [], str(e)
        problems.append(f"读不到 findings 表（{e}）：无法判断覆盖，按未覆盖处理")

    # 空台账 + 没有分配风险 = 什么都没证明。旧实现返回 ok:true，等于把
    # 「没做过」报成「已覆盖」。
    if not rows and not (assigned_risks or []):
        problems.append("台账为空且未指定 --assigned-risk：没有任何覆盖证据")

    # 1) finding 未记账
    untracked: list[dict[str, Any]] = []
    for f in findings:
        # 必须**逐条**对上，不能靠「同 vulnclass 有一条 reported」就算覆盖。
        # 原实现里有 `or (outcome=="reported" and 同 vulnclass)`，导致一条
        # /ftp + info-disclosure 的 reported 把 #7/#8/#9/#10 全部认成已覆盖，
        # 其中 #8（encryptionkeys）和 #9（JWT MD5）是完全不同的漏洞（实测踩过）。
        #
        # 认「已覆盖」只接受两种：
        #   a) 台账 evidence/note 里明确写了 finding_id=<id>
        #   b) 台账行的 surface 与该 finding 的资产路径有实际重叠（非空）
        fid_mark = f"finding_id={f['finding_id']}"
        hit = False
        for r in rows:
            if not _risk_matches(r.get("risk", ""), f["vulnclass"]):
                continue
            blob = f"{r.get('evidence') or ''} {r.get('note') or ''}"
            if fid_mark in blob:
                hit = True
                break
            if r.get("outcome") == "reported" and _surface_overlaps(r.get("surface", ""), f):
                hit = True
                break
        if not hit:
            untracked.append(f)
    if untracked:
        problems.append(f"{len(untracked)} 条 finding 未在台账登记")

    # 2) 台账声称 reported 但没有对应 finding
    claimed_only: list[dict[str, Any]] = []
    for r in rows:
        if r.get("outcome") != "reported":
            continue
        if not any(_risk_matches(r.get("risk", ""), f["vulnclass"]) for f in findings):
            claimed_only.append(r)
    if claimed_only:
        problems.append(f"{len(claimed_only)} 行台账声称 reported，但任务内无对应 vulnclass 的 finding")

    # 3) 分配了但没记录
    if s["gaps"]:
        problems.append(f"{len(s['gaps'])} 个被分配的风险类无任何记录")

    # 4) 未结项
    if s["open_items"]:
        problems.append(f"{len(s['open_items'])} 条 needs_follow_up 未关闭")

    return {
        "task_id": task_id,
        "ledger": path,
        "ledger_exists": os.path.isfile(path),
        "rows_total": len(rows),
        "findings_total": len(findings),
        "by_outcome": s["by_outcome"],
        "gaps": s["gaps"],
        "open_items": s["open_items"],
        "untracked_findings": untracked,
        "claimed_only_rows": claimed_only,
        "problems": problems,
        "findings_error": findings_error,
        "ok": not problems,
        "verdict": (
            "覆盖台账健康：无缺口、无未结项、finding 与台账一致"
            if not problems
            else "覆盖台账存在问题，不能声称「已覆盖」"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="覆盖台账体检（对照 findings 表）")
    ap.add_argument("--task-id", required=True, type=int)
    ap.add_argument("--ledger", default="")
    ap.add_argument("--assigned-risk", action="append", default=[])
    ap.add_argument("--dsn", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    r = report(a.task_id, a.ledger, a.assigned_risk, a.dsn or None)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"task {r['task_id']} 覆盖体检")
        print(f"  台账: {r['ledger']} (exists={r['ledger_exists']}) 行数={r['rows_total']}")
        print(f"  finding: {r['findings_total']} 条")
        print(f"  分布: {r['by_outcome']}")
        if r["untracked_findings"]:
            print("  未记账 finding:")
            for f in r["untracked_findings"]:
                print(f"    - #{f['finding_id']} {f['vulnclass']} {f['name'][:60]}")
        if r["claimed_only_rows"]:
            print("  空口覆盖（台账 reported 但无 finding）:")
            for x in r["claimed_only_rows"]:
                print(f"    - {x.get('surface')} / {x.get('risk')}")
        if r["gaps"]:
            print("  缺口:")
            for g in r["gaps"]:
                print(f"    - {g}")
        if r["open_items"]:
            print("  未结项:")
            for x in r["open_items"]:
                print(f"    - {x.get('surface')} / {x.get('risk')}: {x.get('note') or x.get('evidence')}")
        print(f"  结论: {r['verdict']}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
