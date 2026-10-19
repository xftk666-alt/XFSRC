#!/usr/bin/env python3
"""覆盖台账：记录「测过什么」，而不只是「找到什么」。

为什么需要它：
  frontier_open=0 + goals 全 met 看起来是「完美收官」，但完全无法回答
  「/api/Users 测过 IDOR，那 BFLA 测了吗？」—— 0 finding 不等于干净，
  可能只是没测。三家 SRC 里，漏测不封号，但「声称测过而没测」就是谎报。

台账格式（每个任务一份 coverage.json）：
  {
    "task_id": 6,
    "updated_at": "...",
    "rows": [
      {"surface": "/api/Users", "risk": "idor", "outcome": "reported",
       "evidence": "finding_id=11", "note": "...", "ts": "..."}
    ]
  }

outcome 枚举（与 src-coverage skill 一致）：
  reported        确认并已上报
  no_issue_found  测了，没发现
  ruled_out       测了，并点名了具体控制证明不可利用
  not_applicable  该 surface 不适用这类风险（要写理由）
  needs_follow_up 看起来可疑但证据不足 —— 必须留档，不许静默丢弃

用法：
  python3 coverage_record.py --task-id 6 --surface /api/Users --risk bfla \
      --outcome no_issue_found --evidence "GET /api/Users as customer returned 403 for admin ops"
  python3 coverage_record.py --task-id 6 --dump
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

OUTCOMES = ("reported", "no_issue_found", "ruled_out", "not_applicable", "needs_follow_up")

# 常见风险面：用于 coverage_report 判断「分配了但没记录」
RISK_AREAS = (
    "idor", "bfla", "xss", "ssrf", "sqli", "nosqli", "ssti", "xxe",
    "csrf", "race_conditions", "mass_assignment", "http_request_smuggling",
    "path_traversal", "insecure_file_upload", "open_redirect",
    "prototype_pollution", "argument_injection", "header_injection",
    "auth", "jwt", "oauth", "saml", "graphql", "business_logic",
    "info_disclosure", "subdomain_takeover", "cache_poisoning",
    "cache_deception", "cors", "host_header_injection",
    "llm_prompt_injection",
)


def default_path(task_id: int) -> str:
    """台账位置必须与 cwd 无关。

    原来在 /app/data/tasks/<id>/ 不存在时回退到 os.getcwd()，
    结果同一个任务在不同目录下跑，会各自长出一份台账，
    汇总时互相看不见（实测踩过）。现在固定为任务目录，目录不存在就建。
    """
    p = f"/app/data/tasks/{task_id}/coverage.json"
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
    except Exception:
        # 任务目录不可写时才退到工作目录，但要留下可读痕迹
        return os.path.join(os.getcwd(), f"coverage-task{task_id}.json")
    return p


def load(task_id: int, path: str = "") -> dict[str, Any]:
    p = path or default_path(task_id)
    if not os.path.isfile(p):
        return {"task_id": task_id, "updated_at": None, "rows": []}
    try:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
        doc.setdefault("task_id", task_id)
        doc.setdefault("rows", [])
        return doc
    except Exception:
        return {"task_id": task_id, "updated_at": None, "rows": []}


def _atomic_write(path: str, doc: dict[str, Any]) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".coverage-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def record(
    task_id: int,
    surface: str,
    risk: str,
    outcome: str,
    evidence: str = "",
    note: str = "",
    path: str = "",
) -> dict[str, Any]:
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome 必须是 {OUTCOMES} 之一，收到 {outcome!r}")
    if not (surface or "").strip():
        raise ValueError("surface 不能为空")
    if not (risk or "").strip():
        raise ValueError("risk 不能为空")
    # needs_follow_up / ruled_out 必须带说明，否则等于没记
    if outcome in ("ruled_out", "needs_follow_up") and not (evidence or note).strip():
        raise ValueError(f"outcome={outcome} 必须给 evidence 或 note（点名具体控制/缺口）")

    p = path or default_path(task_id)
    doc = load(task_id, p)
    row = {
        "surface": surface.strip(),
        "risk": risk.strip().lower(),
        "outcome": outcome,
        "evidence": evidence.strip(),
        "note": note.strip(),
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    # 同一 surface+risk 覆盖旧结论（保留最新判断）
    doc["rows"] = [
        r for r in doc.get("rows", [])
        if not (r.get("surface") == row["surface"] and (r.get("risk") or "").lower() == row["risk"])
    ]
    doc["rows"].append(row)
    doc["updated_at"] = row["ts"]
    doc["task_id"] = task_id
    _atomic_write(p, doc)
    return {"ok": True, "path": p, "row": row, "rows_total": len(doc["rows"])}


def summary(task_id: int, path: str = "", assigned_risks: list[str] | None = None) -> dict[str, Any]:
    """汇总：已覆盖、可疑未结、以及「分配了但没有记录」的缺口。"""
    p = path or default_path(task_id)
    doc = load(task_id, p)
    rows = doc.get("rows", [])

    surfaces = sorted({r.get("surface") for r in rows if r.get("surface")})
    risks = sorted({(r.get("risk") or "").lower() for r in rows if r.get("risk")})
    by_outcome: dict[str, int] = {}
    for r in rows:
        by_outcome[r.get("outcome", "?")] = by_outcome.get(r.get("outcome", "?"), 0) + 1

    # 缺口：被分配了某类风险，但台账里一行都没有
    gaps: list[str] = []
    for r in assigned_risks or []:
        rl = r.strip().lower()
        if rl and rl not in risks:
            gaps.append(f"分配了 {rl}，但台账无任何 {rl} 记录")

    open_items = [
        r for r in rows if r.get("outcome") in ("needs_follow_up",)
    ]

    return {
        "task_id": task_id,
        "path": p,
        "exists": os.path.isfile(p),
        "rows_total": len(rows),
        "surfaces": surfaces,
        "risks": risks,
        "by_outcome": by_outcome,
        "gaps": gaps,
        "open_items": open_items,
        "clean_claim_allowed": len(rows) > 0 and not gaps and not open_items,
        "verdict_note": (
            "台账为空：不能声称测过任何风险面"
            if not rows
            else ("存在缺口/未结项，不能声称「已覆盖」" if (gaps or open_items) else "覆盖台账无缺口")
        ),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="覆盖台账：记录 surface × risk × outcome")
    ap.add_argument("--task-id", required=True, type=int)
    ap.add_argument("--surface", default="")
    ap.add_argument("--risk", default="")
    ap.add_argument("--outcome", default="", choices=[""] + list(OUTCOMES))
    ap.add_argument("--evidence", default="")
    ap.add_argument("--note", default="")
    ap.add_argument("--assigned-risk", action="append", default=[], help="本任务被分配的风险类（可多次）")
    ap.add_argument("--dump", action="store_true", help="打印台账")
    ap.add_argument("--summary", action="store_true", help="打印汇总与缺口")
    ap.add_argument("--path", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.dump:
        doc = load(a.task_id, a.path)
        print(json.dumps(doc, ensure_ascii=False, indent=2))
        return 0

    # 明确要写入（给了 risk/outcome）但 surface 为空 → 必须报错，不能悄悄降级成 summary
    if not a.surface and (a.risk or a.outcome):
        print(json.dumps({"ok": False, "error": "surface 不能为空"}, ensure_ascii=False))
        return 2

    if a.summary or not a.surface:
        s = summary(a.task_id, a.path, a.assigned_risk)
        if a.json:
            print(json.dumps(s, ensure_ascii=False, indent=2))
        else:
            print(f"task {s['task_id']} 覆盖台账: {s['path']} (exists={s['exists']})")
            print(f"  行数={s['rows_total']}  surface={len(s['surfaces'])}  risk={len(s['risks'])}")
            print(f"  分布: {s['by_outcome']}")
            if s["gaps"]:
                print("  缺口:")
                for g in s["gaps"]:
                    print(f"    - {g}")
            if s["open_items"]:
                print(f"  未结项 {len(s['open_items'])} 条:")
                for r in s["open_items"]:
                    print(f"    - {r.get('surface')} / {r.get('risk')}: {r.get('note') or r.get('evidence')}")
            print(f"  结论: {s['verdict_note']}")
        return 0 if s["clean_claim_allowed"] or s["rows_total"] else 1

    try:
        r = record(a.task_id, a.surface, a.risk, a.outcome or "no_issue_found",
                   a.evidence, a.note, a.path)
    except ValueError as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 2
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else f"[ok] {r['row']['surface']} / {r['row']['risk']} -> {r['row']['outcome']}  ({r['rows_total']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
