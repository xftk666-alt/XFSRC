---
name: src-coverage
description: 覆盖台账纪律：记录 surface × risk_area × outcome，区分「测过且干净」和「根本没测」。任务收尾时必须附覆盖摘要，被分配了某类风险却无任何记录视为缺口。用于海外 SRC 任务完成定义、避免把漏测谎报成已覆盖。当任务接近完成、要宣布「测完了」、或需要判断还差哪些风险面时使用。
---
# src-coverage — 覆盖台账（测过什么，而不只是找到什么）

## 问题

任务图显示 `frontier_open=0`、所有 goal 都 `met`、有 16 条 finding，看起来完美收官。
但它**无法回答**：

- `/api/Users` 测过 IDOR，那 **BFLA** 测了吗？
- `/ftp` 测过信息泄露，那 **路径穿越** 测了吗？
- `/rest/products/search` 测过 XSS，那 **SQLi / NoSQLi** 测了吗？

**0 finding ≠ 干净，可能只是没测。**

在 SRC 里，漏测不会封号（只是拿不到赏金），但**声称测过而实际没测 = 谎报**，这才是要防的。

## 台账格式

每个任务一份 `coverage.json`：

```json
{
  "task_id": 6,
  "updated_at": "2026-10-19T12:00:00+00:00",
  "rows": [
    {
      "surface": "/api/Users",
      "risk": "idor",
      "outcome": "reported",
      "evidence": "finding_id=11",
      "note": "",
      "ts": "2026-10-19T11:58:00+00:00"
    }
  ]
}
```

## outcome 五态（必须严格使用）

| outcome | 含义 | 要求 |
|---|---|---|
| `reported` | 确认并已上报 | `evidence` 必须含 `finding_id=N` |
| `no_issue_found` | 测了，没发现 | `evidence` 写清测了什么（请求/响应特征） |
| `ruled_out` | 测了，并点名具体控制证明不可利用 | **必须点名具体位置的具体控制**（见 `src-closure`） |
| `not_applicable` | 该 surface 不适用这类风险 | 必须写理由（如「纯静态资源，无服务端处理」） |
| `needs_follow_up` | 看起来可疑但证据不足 | **必须留档，不许静默丢弃** |

**只有这五态。** 不允许写「大概没问题」「应该安全」「测过了」。

### 补充：`not_applicable` 必须过「证据反驳」

写 `not_applicable` 时，系统/复核者会拿**已观测到的证据**来反驳。被反驳则该行作废，必须去测。

| 你写的 N/A | 什么证据会反驳它 |
|---|---|
| 「无 API 面，不测接口类」 | 任何 `/api/`、`/graphql`、`/rest/` 的响应或 JS 里的接口字符串 |
| 「无登录功能，不测认证」 | 任何 `Set-Cookie`、`/login`、`/token`、`Authorization` 响应头 |
| 「无文件上传」 | 任何 `multipart/form-data` 表单或上传接口 |
| 「无 WebSocket」 | 任何 `Upgrade: websocket` 或 `wss://` |
| 「无缓存层，不测缓存投毒」 | 任何 `X-Cache`/`CF-Cache-Status`/`Age`/`Vary` 响应头 |
| 「无跨域，不测 CORS」 | 任何 `Access-Control-Allow-*` 响应头 |
| 「无 SSO，不测 OAuth/SAML」 | 任何 `/oauth`、`/authorize`、`/.well-known/openid-configuration`、`SAMLResponse` |

**规则：N/A 是「有证据证明不存在」，不是「我没看见」。** 被反驳后必须改成 `needs_follow_up` 并实际去测。

### `blocked` ≠ 没测

`needs_follow_up` 里要区分两种，别混：

| 子状态 | 含义 | 收尾处理 |
|---|---|---|
| `blocked_<原因>` | 想测但被卡住（缺账号、WAF 429、需要审批） | 必须在收尾报告里单列，并说明卡在哪一步 |
| `open_proof_gap` | 测了但证据不足 | 必须留档，写明缺什么证据 |

**不能把 blocked 写成 no_issue_found。**「被 WAF 拦了」不是「测过且干净」。

## 怎么写

```bash
# 记录
python3 /app/skills/src-retest/scripts/coverage_record.py \
  --task-id 6 --surface /api/Users --risk bfla \
  --outcome no_issue_found \
  --evidence "customer token GET /api/Users returned 403 on admin-only fields; POST /api/Users 403"

# 可疑未结
python3 /app/skills/src-retest/scripts/coverage_record.py \
  --task-id 6 --surface /ftp --risk path_traversal \
  --outcome needs_follow_up \
  --note "%2500.md 已证明 NUL 截断；未测 ..%2f 与 UTF-8 变体"

# 体检（对照 findings 表，找三类问题）
python3 /app/skills/src-retest/scripts/coverage_report.py \
  --task-id 6 --assigned-risk idor --assigned-risk bfla --assigned-risk xss
```

`coverage_report` 会检查：

1. **未记账 finding** —— 已 `report_finding` 但台账没对应行
2. **空口覆盖** —— 台账写 `reported`，但任务内没有对应 vulnclass 的 finding
3. **缺口** —— 被分配了某类风险，台账一行都没有
4. **未结项** —— `needs_follow_up` 未关闭

退出码 0 = 健康；非 0 = 有问题（可当完成门禁用）。

**fail-closed 语义**：读不到 findings 表、或台账为空且没给 `--assigned-risk`，
一律非 0（「查不到」不等于「已覆盖」）。

### 全景体检（收尾必跑）

`coverage_report` 只看「台账 vs findings」，回答不了「该测的类有没有漏」。
收尾时把两个脚本一起跑（`coverage_report.py` + `taxonomy_gap.py`），或直接看下面这张表：

它把两套账合并：

| 来源 | 检查什么 |
|---|---|
| `coverage_report` | 未记账 finding / 空口覆盖 / 缺口 / 未结项 |
| `taxonomy_gap`（`src-taxonomy`） | taxonomy 里 `decision=covered|partial` 的类，台账里完全没有记录 |

退出码 0 才能宣布完成。若 taxonomy 缺口不为 0，必须逐族补测或写 `not_applicable` + 理由。

**注意**：taxonomy 缺口是「族级」判断（某族在台账里一行都没有才算缺口）。
族内个别类没测时，用 `taxonomy_gap.py --family 14` 看细节，并在覆盖摘要里说明取舍。

## 完成定义必须包含

任务收尾时，报告里必须附：

```
## 覆盖摘要
- 已测 surface：12 个
- 已测风险面：idor, bfla, xss, ssrf, business_logic, info_disclosure
- reported：16
- no_issue_found：23
- ruled_out：4
- not_applicable：2
- needs_follow_up：1（/ftp × path_traversal，未测编码变体）
- blocked：1（/api/admin × bfla，缺管理员测试账号）
- 缺口：无
- 收尾状态：completed / completed_with_blocked_work / incomplete
```

**收尾状态必须显式写一个**（三选一，不许含糊）：

| 状态 | 含义 | 何时用 |
|---|---|---|
| `completed` | 分配的风险面全部有结论，无缺口、无 blocked | 真正测完 |
| `completed_with_blocked_work` | 主要面测完，但有明确 blocked 项 | 可交付，但报告要列 blocked |
| `incomplete` | 还有缺口，或收尾门禁被耗尽 | **不许说「测完了」** |

**缺口不为空、未结项不为空、或状态是 `incomplete` 时，不允许说「测完了」。**

## 风险面清单（分配时参考）

```
idor  bfla  xss  ssrf  sqli  nosqli  ssti  xxe  csrf
race_conditions  mass_assignment  http_request_smuggling
path_traversal  insecure_file_upload  open_redirect
prototype_pollution  argument_injection  header_injection
auth  jwt  oauth  saml  graphql  business_logic  info_disclosure
subdomain_takeover  cache_poisoning  cache_deception  cors
host_header_injection  llm_prompt_injection
```

不必每个 surface 都测全部风险。**但每个「分配了的」风险必须有一行记录。**

## 常见错误

| 错误 | 为什么不行 |
|---|---|
| 「这个接口肯定有 IDOR，但我没测」 | 要么测要么记 `needs_follow_up` |
| 「扫过了没报错，算 no_issue_found」 | 扫描器没报 ≠ 测过；要写清测了什么 |
| 「not_applicable 不用写理由」 | 不写理由等于没记 |
| 事后一次性补记全部台账 | 台账要在每次测完后立即写；事后补记容易编造 |
| 台账写 reported 但没 finding_id | `coverage_report` 会判为「空口覆盖」 |

## 与其它 skill 的关系

- `src-closure`：单个候选的三态收敛（本 skill 是 surface 级台账）
- `src-triage`：判重与提交决策
- `src-report-writing`：报告里附覆盖摘要
