#!/usr/bin/env python3
"""给猎人看的一页纸。不展示 HMAC/gate 细节。"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from retest_strict import evaluate, excerpt_around, load_json, load_pack, read_body  # noqa: E402
from submit_brief import brief as submit_brief  # noqa: E402


def empty(v: str | None) -> bool:
    return v is None or not str(v).strip()


def load_verdict(outdir: str) -> dict[str, Any] | None:
    """读**已验签**的 verdict.json。

    旧实现直接读 payload，于是手写的 {"payload":{"verdict":"reproduced"}} 也能让
    卡片显示「机器判定：复测成立」——卡片是给人看的，不能展示未签名结论。
    """
    path = os.path.join(outdir, "verdict.json")
    if not os.path.isfile(path):
        return None
    try:
        raw = load_json(path)
    except Exception:
        return None
    try:
        from evidence_seal import verify_document
    except Exception:
        return None
    ok, _ = verify_document(raw)
    if not ok or not isinstance(raw.get("payload"), dict):
        return None
    return raw["payload"]


def card(
    outdir: str,
    victim_marker: str = "",
    kind: str = "",
    attack: str = "",
    control: str = "",
    title: str = "",
    impact: str = "",
    claimed_severity: str = "",
    task_id: str = "",
    _dup_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    outdir = os.path.abspath(outdir)
    live = evaluate(outdir, kind, victim_marker, attack, control)
    pack = None
    try:
        pack = load_pack(outdir)
    except FileNotFoundError:
        pack = {"cases": []}
    verdict = load_verdict(outdir)
    marker = (victim_marker or live.get("victim_marker") or "").strip()
    attack_n = live.get("attack")
    control_n = live.get("control")
    a_ex = excerpt_around(read_body(outdir, attack_n), marker) if attack_n and marker else None
    c_ex = "对照里没有这串（这是好事）"
    if control_n and marker:
        raw_c = read_body(outdir, control_n)
        if marker.encode("utf-8") in raw_c:
            c_ex = excerpt_around(raw_c, marker)
        else:
            c_ex = "ABSENT（对照请求里没有受害者字段）"

    lab = bool(live.get("lab"))
    ok = bool(live.get("ok"))
    rec = live.get("recommended_verdict") or "inconclusive"
    v_verdict = (verdict or {}).get("verdict") if verdict and not verdict.get("rejected") else None

    sb = submit_brief(
        lab=lab,
        gate_ok=ok,
        recommended=rec,
        kind=kind,
        title=title,
        impact=impact,
        claimed_severity=claimed_severity,
        task_id=task_id,
        pack=pack,
        _dup_rows=_dup_rows,
    )
    submit_action = sb.get("submit_action")

    if lab:
        user_action = "不要交三家"
        user_reason = "这是靶场/内网练习，技术上即使是真洞也不能交 HackerOne / Bugcrowd / Intigriti。"
        traffic_light = "red"
    elif rec == "not_a_vuln" or (not ok and rec == "not_a_vuln"):
        user_action = "不要交"
        user_reason = "独立复测证明这不是漏洞，或没有跨过安全边界（常见：只有 HTTP 200、内容和首页一样、看到的是自己的数据）。"
        traffic_light = "red"
    elif not ok:
        user_action = "不要交"
        user_reason = "证据不够：原始包不完整、对照失败、或无法证明读到了别人的数据。不是「已修复」，是「现在不能当洞交」。"
        traffic_light = "red"
    elif submit_action == "do-not-submit":
        user_action = "不要交"
        user_reason = "；".join(sb.get("reasons") or ["三家常见 N/A 或无安全影响。"])
        traffic_light = "red"
    elif submit_action == "needs-human":
        user_action = "先别交，你自己看一眼"
        user_reason = "机器只能给上限，不能定价、也不能查三家是否重复。" + (
            " " + "；".join(sb.get("reasons") or [])
        )
        traffic_light = "yellow"
    else:
        user_action = "建议你自己去平台提交"
        user_reason = "机器已核对：攻击响应里出现下面这串专属字段，对照请求里没有。你只需确认这串是测试号 B 的数据、不是无关公开信息，然后把报告粘贴到已加入的 program。"
        traffic_light = "green"

    you_check = None
    if traffic_light in ("green", "yellow"):
        you_check = {
            "只看这一行": a_ex or "（正文里找到了 marker，但摘录失败，请让助手重打 preview）",
            "问自己": "这串是不是我自己建的测试号 B 的邮箱/ID/订单？如果是公开昵称、是我自己的数据、或是真实路人用户——不要交。",
            "对照": c_ex,
        }

    zh_verdict = {
        "reproduced": "复测成立",
        "not_a_vuln": "不是漏洞",
        "fixed": "看起来已修复",
        "inconclusive": "这次没打清楚",
    }.get(v_verdict or rec, rec)

    md = []
    md.append("# 猎人卡片（你只看这一页）")
    md.append("")
    md.append(f"## 结论：{user_action}")
    md.append("")
    md.append(user_reason)
    md.append("")
    if title:
        md.append(f"**标题草稿：** {title}")
        md.append("")
    if impact:
        md.append(f"**影响（不夸大）：** {impact}")
        md.append("")
    md.append(f"- 机器判定：{zh_verdict}")
    md.append(f"- 靶场：{'是（禁止交三家）' if lab else '否'}")
    if marker:
        md.append(f"- 核对关键字：`{marker}`")
    cap = sb.get("severity_ceiling")
    md.append(f"- 严重度上限（不是赏金）：`{cap}`；机器不标价")
    dups = sb.get("duplicate_in_task") or []
    if dups:
        md.append("- 本任务疑似重复：")
        for d in dups[:5]:
            md.append(f"  - finding #{d.get('finding_id')} `{d.get('vulnclass')}` {d.get('summary')}")
    if sb.get("claimed_too_high"):
        md.append(f"- 声称严重度被压回上限：`{claimed_severity}` > `{cap}`")
    md.append("")
    if you_check:
        md.append("## 你只需核对 10 秒")
        md.append("")
        md.append("攻击响应里的原文摘录：")
        md.append("")
        md.append("```")
        md.append(str(you_check["只看这一行"]))
        md.append("```")
        md.append("")
        md.append(you_check["问自己"])
        md.append("")
        md.append(f"对照：{you_check['对照']}")
        md.append("")
        if traffic_light == "yellow":
            md.append("核对完后：先别点提交。看本任务是否重复、声称严重度是否夸大、program 政策是否收这类。机器不标价。")
        else:
            md.append("核对完后：把助手给你的报告全文粘贴到 HackerOne / Bugcrowd / Intigriti。助手不能替你点提交。")
    else:
        md.append("## 你不用做任何提交")
        md.append("")
        md.append("不要把这条拿到三家去交。若你仍觉得它是洞，把这条卡片发回给助手，说明你怀疑哪一点。")
    md.append("")
    md.append("你不需要：跑命令、看 HMAC、看 gate.json、自己抓包。那些由助手完成。")

    reasons = live.get("reasons") or []
    brief_reasons = [r for r in reasons if "lab/CTF" not in r][:4]

    return {
        "user_action": user_action,
        "traffic_light": traffic_light,
        "user_reason": user_reason,
        "machine_verdict": v_verdict or rec,
        "lab": lab,
        "gate_ok": ok,
        "victim_marker": marker,
        "you_check": you_check,
        "title": title or None,
        "impact": impact or None,
        "submit_action": submit_action,
        "severity_ceiling": sb.get("severity_ceiling"),
        "price": None,
        "duplicate_in_task": dups,
        "claimed_too_high": sb.get("claimed_too_high"),
        "hidden_reasons": brief_reasons + list(sb.get("reasons") or []),
        "markdown": "\n".join(md),
        "note": "给用户只展示 markdown。不要主动展示 hmac/challenge/seal。机器不标价。",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--outdir", default="")
    p.add_argument("--victim-marker", default="")
    p.add_argument("--kind", default="")
    p.add_argument("--attack", default="")
    p.add_argument("--control", default="")
    p.add_argument("--title", default="")
    p.add_argument("--impact", default="")
    p.add_argument("--claimed-severity", default="")
    p.add_argument("--task-id", default="")
    args = p.parse_args()
    if empty(args.outdir):
        print("ERROR: outdir 必填", file=sys.stderr)
        return 2
    if empty(args.victim_marker):
        print("ERROR: victim_marker 必填（助手填受害者邮箱/机密，用户只看卡片）", file=sys.stderr)
        return 2
    out = card(
        args.outdir,
        args.victim_marker,
        args.kind,
        args.attack,
        args.control,
        args.title,
        args.impact,
        args.claimed_severity,
        args.task_id,
    )
    print(out["markdown"])
    print("\n---\n")
    print(json.dumps({k: v for k, v in out.items() if k != "markdown"}, ensure_ascii=False, indent=2, default=str))
    # 红灯必须反映到退出码：编排器/脚本按 rc 判断成败，恒返回 0 会让一张
    # 「禁止提交」的卡片看起来像成功。
    return 0 if out.get("submit_action") != "do-not-submit" else 5


if __name__ == "__main__":
    raise SystemExit(main())
