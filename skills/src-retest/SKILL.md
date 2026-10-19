---
name: src-retest
description: 漏洞详情页「查看报告 → 漏洞复测」独立会话的硬门禁。在独立会话中验证当前状态，保留每次结论与证据。必须 HMAC 封印原始包、字段级对照、retest_strict_gate、retest_verdict、hunter_card；用 record_finding_retest_result 写入。禁止口述、禁止只看 HTTP 200、禁止开洞 worker 复测自己。开洞前先走 src-triage。
---

# 独立二次复测（尽量接近真人取证，仍不能代你点提交）

给平台 **retester** Agent（漏洞详情 → 查看报告 → **漏洞复测** 按钮拉起的独立会话）。

用户入口就是这个按钮：每次点一次 = 一条新会话 + `finding_retests` 里一条结论。原报告不变。  
编排 Auto **不要**在聊天里打请求、也**不要**用 spawn_task 冒充复测。用户不会操作时：会话结束只给 `hunter_card`，提交他自己去三家点。

**能替代**：真人再打一遍、对照实验、把原始包/截图留在磁盘、机器否决谎报和大部分误报。  
**不能替代**：你看一眼 `response.body` 里是不是别人的数据，以及在 H1/Bugcrowd/Intigriti 网页上点提交。

配套：开洞前 `src-triage` → 本技能 → 写报告 `src-report-writing`。

---

## 0. 硬门槛（文件不在 = 结论作废）

| 文件 | 谁写 | 没有它就不能 |
|---|---|---|
| `cases/*/response.body` + `meta.json` + **`seal.json`（HMAC）** | 仅 `http_evidence_record` / `browser_xss_evidence` | 一切。手写/改 body 后 seal 对不上 |
| `compare-*-vs-*.json` 且含 **字段**断言，期望值=victim_marker | `http_evidence_compare` | HTTP 类 reproduced |
| **签名** `gate.json`（含 `challenge`） | **`retest_strict_gate`** | 签字。**verdict 不信这个文件的 ok 字段，会现场重算** |
| 签名 `verdict.json` | **`retest_verdict`**（reproduced 必须带 victim_marker） | 向用户汇报 |
| 签名 `signoff.json` | **`retest_signoff`**（口令+challenge） | `ready` |

对抗测试（`scripts/test_retest_adversarial.py`）覆盖：泛词 marker、篡改 body/request、手写 gate、无封印、纯状态码、SPA fallback、假 signoff、compare 绑错字符串、缺 control-self、把自己的数据当 IDOR、请求回显、不同 origin、过期 JWT。回归必须全绿。

Agent **禁止**：

- 把 worker Markdown / 聊天复述写成 reproduced
- 用 HTTP 200、`ok`、`id`、`true`、`customer` 当 victim_marker
- 手写 `gate.json` / `seal.json` / `signoff.json` 或改 `response.body` 后再签
- 代用户填写签字口令或 challenge
- 靶场 / `not_a_vuln` 写成 ready
- gate 失败后改口说「其实过了」

---

## 1. 铁律

1. **新会话、新账号、新 token。** 禁止复用 worker 落盘的 JWT / 订单号。
2. **attack + control，只改一个变量**（token / id / payload 三选一）。
3. **证据在磁盘上。** 禁止只把 curl 输出粘进 Markdown。
4. **victim_marker 必须是受害者专属字段**：B 的邮箱、长 UserId、订单号、dialog.message、密钥片段。≥8 字符或含 `@`。
5. **影响只写本次 `response.body` 里的值。**
6. **教学靶场永远 `submit_advice=never`。**
7. 一次失败或 WAF ≠ 已修复（`inconclusive`）。不是洞要写 `not_a_vuln`，不要用 inconclusive 遮羞。
8. **你已经在漏洞复测独立会话里。** 不要 `spawn_task`，不要 `report_finding`。结论：磁盘证据包 + `record_finding_retest_result` + `hunter_card`。平台 verdict 只有 reproduced / fixed / inconclusive；不是洞时用 inconclusive，summary 以【不是漏洞】开头。

   > **`record_finding_retest_result` 是唯一落库动作，不可跳过。**
   > 顺序固定：`retest_strict_gate` → `evidence_gate` → `retest_verdict` → `hunter_card` → **`record_finding_retest_result`**。
   > 只跑闸门和 hunter_card 就收尾，平台会把 `finding_retests.status` 置为 `failed`
   > （error: Agent 未保存复测结论），此时任何"已完成/已保存"的自我宣告都是假的。
   > 2026-10-19 复测 #8 就是这样失败的：闸门全过、卡片已出、record 零调用。
9. 先对照 `src-triage`「直接丢弃」目录。命中则 `not_a_vuln`。

---

## 2. 证据包目录

```
/app/data/evidence/task-<task_id>/finding-<finding_id>/
  pack.json
  cases/<name>/request.txt
  cases/<name>/response_headers.txt
  cases/<name>/response.body      ← 硬证据
  cases/<name>/meta.json          ← User-Agent 必须是 artex-http-evidence/1.0
  cases/<name>/seal.json          ← HMAC；record 自动写。缺了或改 body 后失效
  cases/<name>/screenshot.png     ← XSS
  compare-<attack>-vs-<control>.json
  gate.json                       ← HMAC + challenge（12 位）
  verdict.json                    ← HMAC；reproduced 现场重算
  signoff.json                    ← HMAC；口令必须含 challenge
```

无 task 工作目录时用 `/app/data/evidence/finding-<id>/`。

---

## 3. 对照矩阵（字段必须进 compare）

| 类型 | attack | control | victim_marker 例子 | compare 必带 |
|---|---|---|---|---|
| IDOR | A token + B 的 id | **必须** A token + A 的 id（`control-self`）；另加无 token + B 的 id | B 的邮箱（且不得出现在 A 自己的对象里） | `attack_contains=B邮箱`；缺 control-self 直接否决 |
| 垂直越权 | 普通用户调管理接口 | 无 token | 管理面才有的字段 | 同上 |
| JWT alg=none | 伪造 token | 无 token | 伪造身份的 email/role | `attack_contains=该 email` |
| 信息泄露 | GET 敏感路径 | 首页或 404 | 密钥/目录文件名/`ref: refs` | sha256 ≠ 首页 |
| XSS | browser 打开 payload | （dialog 即可） | `document.domain` 的值 | `dialog_executed=true` |
| SSRF | 后端去拉（max_redirs=0） | 无效 URL | 内网文件正文 或 OOB 里后端 UA | 正文含机密 |
| 业务逻辑 | 篡改字段 | 合法值 | 订单金额/角色与 control 不同 | `json_path` 金额 |

**HTTP 200 单独永远不够。** `retest_strict_gate` 会重读 body：attack 必须含 marker，control 必须不含。

---

## 4. 标准流程（按顺序，不许跳）

1. `src-triage`。命中直接丢弃 → `retest_verdict(verdict=not_a_vuln, submit_advice=never)`，仍建议留一条 control 证明「这就是首页/自己的数据」。
2. 自建测试号 A/B，新 token。
3. `http_evidence_record` × (attack + **control-self** + 无 token)。IDOR 缺 `control-self` 闸门直接否决。`expect_contains` 填 **B 的邮箱**，不要填 `200`。
4. `http_evidence_compare(..., attack_contains="<B的邮箱>", bodies_differ="true")`。纯 status 对照会被闸门丢弃。
5. XSS：`browser_xss_evidence`，确认 `dialog_executed=true`。
6. `retest_preview(outdir, victim_marker)` — 把摘录给用户看，**不要自己宣布过了**。
7. `retest_strict_gate(outdir, kind, victim_marker, attack, control)`  
   - `ok=false` → 只能 `not_a_vuln` 或 `inconclusive`  
   - SPA / 正文无 marker / 无 seal / 篡改 → `not_a_vuln` 或 `inconclusive`  
   - 记下返回的 **challenge**（12 位 hex）
8. `evidence_gate(outdir)` 再跑一次（双闸，也会验 seal）。
9. `retest_verdict(outdir, verdict=reproduced, victim_marker=..., submit_advice=needs-human)`  
   - **必须带 victim_marker**：工具会现场重算，手改 `gate.json` 的 `"ok": true` 无效  
   - 想写 `ready` 但没有 HMAC signoff → **拒绝**
10. 向用户展示 preview 摘录 + challenge。非靶场且技术成立时停在 `needs-human`，等用户亲口发送：

    > I inspected the evidence pack and approve submit \<challenge\>  
    > 或：我已核验证据包并批准提交 \<challenge\>

    缺 challenge、Agent 代填、靶场 → `retest_signoff` 失败。通过后再 `retest_verdict(..., submit_advice=ready, victim_marker=...)`。
11. **不要**改原报告、不要再 `report_finding`。系统不能代点三家提交。

---

## 5. 工具最小例子

```
http_evidence_record(
  outdir="/app/data/evidence/finding-11",
  name="attack-read-b",
  method="GET",
  url="https://in-scope/api/Users/37",
  bearer="<A的新token>",
  expect_status="200",
  expect_contains="victim-b@test.local"
)
http_evidence_compare(
  outdir="...",
  attack="attack-read-b",
  control="control-unauth",
  attack_status="200",
  control_status="401",
  attack_contains="victim-b@test.local",
  bodies_differ="true"
)
retest_preview(outdir="...", victim_marker="victim-b@test.local")
retest_strict_gate(outdir="...", kind="idor", victim_marker="victim-b@test.local",
                   attack="attack-read-b", control="control-unauth")
evidence_gate(outdir="...")
retest_verdict(outdir="...", verdict="reproduced", submit_advice="needs-human",
               victim_marker="victim-b@test.local",
               summary="attack body 含 victim-b@test.local，unauth 401")
```

XSS：

```
browser_xss_evidence(outdir="...", name="xss-search", url="https://in-scope/#/search?q=...")
retest_strict_gate(outdir="...", kind="xss", victim_marker="<dialog.message 原文>")
```

签字（**仅当用户刚刚在对话里发送了整句口令+challenge**）：

```
retest_signoff(outdir="...", phrase="我已核验证据包并批准提交 a1b2c3d4e5f6")
retest_verdict(outdir="...", verdict="reproduced", submit_advice="ready",
               victim_marker="victim-b@test.local", summary="...")
```

口令不对、缺 challenge、gate 失败、HMAC 不对、靶场 → `retest_signoff` 返回 ok=false。**禁止编造 phrase / challenge。**

---

## 6. verdict 与 submit_advice

| verdict | 何时 | 允许的 advice |
|---|---|---|
| `reproduced` | `gate.json` ok=true，且正文有专属字段 | 靶场=`never`；否则默认 `needs-human`；有 signoff 才 `ready` |
| `not_a_vuln` | 对照失败 / 无安全边界 / SPA / self-XSS / 最佳实践 / 假 SSRF | **必须 never** |
| `fixed` | attack 失败且正向 control 仍成功 | never 或 needs-human |
| `inconclusive` | 目标挂了、缺账号、WAF、工具失败 | never |

`retest_verdict` 会强制：靶场 → never；not_a_vuln → never；ready 无签字 → 拒绝。

---

## 7. 直接否决 reproduced（机器已覆盖的部分）

- 无 `response.body` / 无 `seal.json` / HMAC 对不上（手写或改过 body）
- UA 不是 `artex-http-evidence/1.0`
- victim_marker 是 `200` / `ok` / `id` / `customer` 或过短
- attack 正文无 marker，或 control 里也有同一 marker
- 纯状态码 compare，或 compare 的 contains 不是 victim_marker
- SPA：attack sha256 = 首页
- XSS 无 dialog / 无截图
- 手写 `gate.json`（verdict 现场重算，HMAC 不对则签字失败）
- 用旧 JWT（iat 距 record 超过 2h）、抄旧报告数字
- IDOR 没有 `control-self`（同一 token 读自己的对象）
- control-self 里也有同一 victim_marker（自己的数据）
- victim_marker 出现在 attack 的 URL/请求体（参数回显）
- attack 与 control 不是同一个 origin（本地假服务凑包）
- compare 绑的是另一对 case，不是这次 named attack/control

---

## 8. 本平台工具

| 目的 | 工具 |
|---|---|
| 是不是洞 | 技能 `src-triage` |
| 记 HTTP 原始包 | `http_evidence_record` |
| 字段级对照 | `http_evidence_compare`（必须带 contains/json_path） |
| 人眼预览摘录 | `retest_preview` |
| **硬闸门** | `retest_strict_gate` → `gate.json` |
| 旧闸门（双保险） | `evidence_gate` |
| 写结论 | `retest_verdict` → `verdict.json` |
| 用户签字 | `retest_signoff` → `signoff.json` |
| XSS | `browser_xss_evidence` |
| JWT | `jwt_decode` |
| OOB | `oob_gen` / `oob_poll` |
| 读原洞 | `get_finding_record` / `get_finding_retest_context` |
| 查重复 | `search_finding_duplicates` / `dup_check` |
| 靶场判定 | `lab_detect`（只读，返回 lab=true/false） |

浏览器 MCP 不能替代 `browser_xss_evidence`。

---

## 9. 对用户怎么说（诚实边界）

- 有签名 `gate.json` + 磁盘原文 ≠ 真人已经在 H1 点过提交。
- 默认最高档是 **`needs-human`**。`ready` 只在用户发送 **口令+challenge** 之后。
- 政策灰区、duplicate、赏金表、夸大影响，机器仍可能放行成 needs-human——**这就是要你看摘录的原因**。
- 同容器里有密钥的进程理论上能重签 seal；对抗测试挡住的是 Write 工具改 body、手写 JSON、跳过 record。物理隔离做不到「绝对万无一失」。
- 系统永远不能登录三家代交。
