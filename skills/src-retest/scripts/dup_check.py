#!/usr/bin/env python3
"""判重自查 CLI：开洞前先问「这个洞是不是已经有了」。

用法：
  python3 dup_check.py --task-id 6 --kind info-disclosure --host 172.18.0.3 --path /ftp
  python3 dup_check.py --task-id 6 --kind idor --host app.example.com --path /api/Users/37 --json

退出码：
  0  没有重复候选
  3  存在重复候选（应先处理重复，不要直接开新 finding）
  4  判重数据源不可用（未知，不等于没有重复）
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from submit_brief import DuplicateLookupUnavailable, lookup_task_duplicates  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="开洞前判重自查")
    ap.add_argument("--task-id", default="")
    ap.add_argument("--kind", required=True, help="vulnclass，如 idor / xss / info-disclosure")
    ap.add_argument("--host", action="append", default=[], help="可多次")
    ap.add_argument("--path", action="append", default=[], help="可多次；短路径（/ftp /api）同样有效")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    try:
        hits = lookup_task_duplicates(a.task_id, a.kind, a.host, a.path)
    except DuplicateLookupUnavailable as e:
        # 判重查不了 ≠ 没有重复。旧实现把它当成 []，于是数据库故障时闸门静默放行。
        if a.json:
            print(json.dumps({"duplicates": [], "count": 0, "error": str(e), "known": False}, ensure_ascii=False, indent=2))
        else:
            print(f"[UNKNOWN] 判重数据源不可用：{e}", file=sys.stderr)
            print("按「可能重复」处理：先人工核对，不要直接开新 finding。", file=sys.stderr)
        return 4
    if a.json:
        print(json.dumps({"duplicates": hits, "count": len(hits)}, ensure_ascii=False, indent=2))
    else:
        if not hits:
            print(f"[OK] 无重复候选（kind={a.kind} host={a.host} path={a.path}）")
        else:
            print(f"[DUPLICATE?] 发现 {len(hits)} 个候选，先按 src-triage 判重五问处理：")
            for h in hits:
                print(f"  #{h['finding_id']} [{h.get('match')}] {h.get('severity')} {h.get('vulnclass')}")
                print(f"      {str(h.get('summary'))[:160]}")
            print("\n五问全「是」→ 不要再开新 finding，改用 update_finding_report / merge_finding_records。")
    return 3 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
