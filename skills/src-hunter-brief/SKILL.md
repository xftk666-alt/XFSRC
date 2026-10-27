---
name: src-hunter-brief
description: 海外 SRC 猎人只需看的一页结论。当复测结束、要告诉用户交或不交、或用户说自己不会复测/只负责提交时使用。禁止甩 HMAC、gate.json、命令行给用户。
---
# 猎人卡片（用户不会复测时的唯一界面）

用户明确：**提交由他自己点；取证、判定、写稿都不会做。** 助手必须把专业细节吞掉，只给一页中文卡片。

配套：用户在漏洞详情点 **漏洞复测** → `retester` 独立会话跑 `src-retest` → 会话里调用 `hunter_card` 给用户看交/不交 → 结论写入 `finding_retests`。  
Auto 聊天不要打请求。

---

## 用户只负责 3 件事（写在每条回复里也行）

1. **加入并被接受** 某个 HackerOne / Bugcrowd / Intigriti program（没加入 = 助手禁止打真实网站）。
2. **看猎人卡片** 上的红灯/绿灯，绿灯时花 10 秒看那一行是不是自己的测试号 B。
3. **自己去平台粘贴提交**（助手永远不能登录三家代点）。

用户不需要：命令、HMAC、gate.json、challenge 口令、自己抓包、自己建证据目录。

---

## 助手必须做的

1. 用户去漏洞详情点「漏洞复测」（独立会话）。Auto 不要在本对话打目标。
2. retester 打完后调用 `hunter_card`，把 **markdown 原文**给用户，不要改口。
3. **禁止**把下列内容贴给用户（除非用户主动问「底层怎么判的」）：
   - `seal.json` / HMAC / fingerprint / challenge
   - `gate.json` 全文、checks 数组
   - Python/bash 命令
   - 让用户「去跑 retest_signoff」
4. 红灯（不要交）：到此停止。可以说「不是洞 / 证据不够 / 这是靶场」。
5. 绿灯（建议你自己去平台提交）：
   - 卡片下面再附一份 **可直接粘贴** 的英文/中文报告（`src-report-writing` 模板）
   - 提醒：只交已加入的 program；不要改严重度往高写
6. 靶场 Juice Shop / CTF：卡片必须是红灯「不要交三家」，即使技术上是真洞。
7. 机器闸门会否决：缺 control-self、把自己的数据当 IDOR、请求回显、不同 origin、过期 JWT、手改 request.txt。这些红灯不要改口说「其实过了」。

`submit_advice=ready` 对「不会操作的猎人」**不要再索要签字口令**。卡片绿灯 + 用户自己点提交 = 流程结束。口令闸门留给以后真想当 retester 的人。

---

## 用户来聊天时怎么接

| 用户说 | 你做 |
|---|---|
| 帮我挖 / 测这个 program | 先确认「已加入且 accepted」。没有 → 只给注册/加入步骤，不发包 |
| 这个洞是真的吗 / 怕误报 | 派独立复测任务 → 只回猎人卡片 |
| 我不会复测 | 「不用你会。你看卡片，交或不交。」 |
| 给我报告 | 仅绿灯才给粘贴稿；红灯给「不要交」 |
| 你帮我交 | 「我不能登录 H1。把下面全文粘贴到 New report。」 |

---

## 工具

`hunter_card(outdir, victim_marker, kind?, attack?, control?, title?, impact?, claimed_severity?, task_id?)`

给用户看 markdown 区块即可。JSON 里的 `hidden_reasons` 是写给助手的，默认不转发。

卡片现在多三件事（**不标价**）：

- 严重度**上限**（缺安全头 / self-XSS / 无资金的输入校验 = 不要交）。
- **本任务**疑似重复（同 vulnclass + 路径）。不是 H1 duplicate 查询。
- 声称严重度高于上限 → 黄灯「先别交」。

机器永远不写金额。跨平台是否重复、赏金表、政策灰区仍是黄灯，由你看。
