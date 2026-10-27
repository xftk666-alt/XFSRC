#!/usr/bin/env python3
"""lab_detect 的只读 CLI 包装。

背景：lab_detect.py 本身只是被 scope_check / report_check / retest_strict /
evidence_gate 内部 import 的库，没有命令行入口。worker 的提示词却要求
在 evidence 里写一行 `lab: false`，而 worker 没有任何原生手段产出这一行，
只能去 Bash 里跑脚本（违反「必须走原生工具」的纪律）。

本 CLI 只做一件事：把同一套判定逻辑暴露成可调用的命令，
让 worker 能拿到权威结论写进 evidence。它**不写任何状态、不做任何放行决定**，
最终是否可提交仍由 report_check / evidence_gate 独立复判
（worker 即使谎报 lab:false，report_check 仍会自己再判一次并拦下）。

用法：
  python3 lab_detect_cli.py --url http://0177.0.0.1:8080/x --json
  python3 lab_detect_cli.py --host 2130706433 --host example.com --json
  python3 lab_detect_cli.py --text "证据正文……" --json
  python3 lab_detect_cli.py --pack /app/data/evidence/finding-1/pack.json --json

退出码：0 = 判定完成（无论是否靶场）；2 = 参数错误。
结论看 JSON 里的 lab 字段，不要用退出码判断是否靶场。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lab_detect import classify_host, is_lab, is_lab_text, lab_reasons  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="靶场识别（只读，供 evidence 引用）")
    ap.add_argument("--url", action="append", default=[], help="待判定的 URL，可多次")
    ap.add_argument("--host", action="append", default=[], help="待判定的主机名/IP，可多次")
    ap.add_argument("--text", default="", help="自由文本（从里面抽 URL/主机名判定）")
    ap.add_argument("--pack", default="", help="证据包 pack.json 路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    a = ap.parse_args(argv)

    targets = list(a.url) + list(a.host)
    if not targets and not a.text and not a.pack:
        print("至少给 --url / --host / --text / --pack 之一", file=sys.stderr)
        return 2

    reasons: list[str] = []
    seen: set[str] = set()

    def _add(rs: list[str]) -> None:
        for r in rs:
            if r not in seen:
                seen.add(r)
                reasons.append(r)

    # 显式给的 host/url 直接判定：lab_reasons 对裸字符串只做 URL 正则提取，
    # 会把 "127.1"、"2130706433" 这类无 scheme 的写法漏掉。
    # classify_host 本身不剥 scheme，所以 URL 要先取出 hostname 再判。
    for t in targets:
        probe = t
        if "://" in t:
            try:
                probe = urlparse(t).hostname or t
            except Exception:  # noqa: BLE001
                probe = t
        r = classify_host(probe)
        if r:
            _add([r])

    if a.text:
        _add(lab_reasons(a.text))

    pack_verdict = None
    if a.pack:
        try:
            with open(a.pack, encoding="utf-8") as fh:
                pack = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            print(f"读取 pack 失败: {exc}", file=sys.stderr)
            return 2
        pack_verdict = bool(is_lab(pack))
        if pack_verdict:
            _add(lab_reasons(pack))

    lab = bool(reasons) or bool(pack_verdict)

    if a.json:
        out = {
            "lab": lab,
            "reasons": reasons,
            "submit_advice": "never" if lab else "allowed_by_lab_check",
            "targets": targets,
        }
        if pack_verdict is not None:
            out["pack_is_lab"] = pack_verdict
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    print(f"lab: {str(lab).lower()}")
    if reasons:
        for r in reasons:
            print(f"  reason: {r}")
    if pack_verdict is not None:
        print(f"  pack_is_lab: {str(pack_verdict).lower()}")
    print(f"  submit_advice: {'never' if lab else 'allowed_by_lab_check'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
