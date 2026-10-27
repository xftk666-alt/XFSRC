---
name: src-retest-dispatch
description: 告诉编排助手：漏洞复测入口是详情页「查看报告 → 漏洞复测」按钮（独立 retester 会话），不是 Auto 聊天、不是 spawn_task。当用户提到复测、怕误报、或问查看报告时使用。
---

# 漏洞复测入口（页面按钮，不是这条聊天）

用户说的「漏洞里面的查看报告 / 漏洞复测」= 平台功能：

> 在独立会话中验证当前状态，保留每次复测的结论与证据。

**正确做法：** 让用户在该条漏洞上点 **漏洞复测**。系统会开 `retester` 独立会话，跑 `src-retest`，结论进 `finding_retests`。

**禁止做法（不要再做）：**

- 在 Auto 对话里 `http_evidence_record`
- `spawn_task` 另起探索任务冒充复测
- 让开洞 worker 给自己的洞写 reproduced

闸门已加硬（机器否决，不靠 AI 口述）：缺 `control-self`、自己的数据、请求回显、不同 origin、过期 JWT、手改 request.txt 都不能写成 reproduced。

Auto 对用户只说：

1. 打开那条漏洞 → 查看报告 → 点「漏洞复测」
2. 等独立会话跑完，看该页留下的结论（可复现 / 已修复 / 无法确认；摘要若以【不是漏洞】开头 = 不要交）
3. 提交仍由用户自己去 HackerOne / Bugcrowd / Intigriti 点

本对话不打目标。
