---
name: src-authz-matrix
description: 海外 SRC 授权范围内的授权矩阵测试（IDOR/BOLA/BFLA 的确定性差分）。用同一请求按 匿名/用户A/用户B/低权限/管理员 多身份重放，比对状态码、长度、正文哈希与关键字段，自动找出权限边界破裂。当已拿到多个测试账号、有 API 清单、或人工换 ID 容易漏测时使用。
---
# src-authz-matrix — 授权矩阵（同一请求，多身份重放）

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program 的 in-scope 资产。目标：把「换 ID 试试」从手工动作变成**可复现、可审计的矩阵**，专治 IDOR / BOLA / BFLA 的漏测与误报。

配套：`src-scope-guard`（发请求前）→ 本技能 → `src-triage` → `src-retest`（证据包）→ `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope，且 program **允许创建多个测试账号**（多数允许，但先看 policy）
- [ ] **只用自己注册的测试账号 A / B**，禁止拿真实用户当受害者
- [ ] 禁止批量遍历 ID 空间（`for i in 1..10000`）。先取 3~5 个自己可控对象 + 1 个他人对象即可证明
- [ ] 禁止对生产做写操作验证（DELETE/PUT 改他人数据）。**读优先**；写操作只在 program 明确允许且用自己账号时做
- [ ] 频率：单接口 ≤ 10 次/分钟；命中 429/403 立即停

---

## 1. 矩阵怎么建

### 1.1 身份维度（行）

| 身份 | 说明 | 必要性 |
|---|---|---|
| `anon` | 无 token / 无 Cookie | 必测 |
| `A-self` | 用户 A 读**自己的**对象 | **必测（control-self）** |
| `B-other` | 用户 A 读**B 的**对象 | 必测（attack） |
| `B-self` | 用户 B 读自己的对象 | 必测（证明对象真实存在） |
| `low-role` | 低权限角色（若产品有角色） | 有则必测 |
| `admin` | 管理员（若 program 提供测试管理员） | 有则测 |

> **没有 `A-self` 对照的 IDOR 结论一律作废。** 因为「A 能读 B 的对象」可能是该对象本来就公开。

### 1.2 对象与动作维度（列）

- 对象类型：用户、订单、发票、文件、消息、项目、组织、地址、支付方式…
- 每个对象至少测：`GET 单对象`、`GET 列表`、`PATCH/PUT`（仅自己账号）、`DELETE`（不测）
- 表示形式变体（漏测高发区）：
  - `/{id}`、`/{id}.json`、`/{id}.xml`
  - `/api/v1/{id}` vs `/api/v2/{id}`
  - `?id=`、`?user_id=`、`?account=`、body 里的 `id`
  - GraphQL：`node(id:)`、`user(id:)`、批量 `nodes(ids:)`
  - 嵌套路由：`/orgs/1/users/2`、`/users/2/orders`
- 方法/头变体：`X-HTTP-Method-Override: PUT`、`Content-Type: application/json` ↔ `form-urlencoded`

### 1.3 结果判定（每格一个结论）

| 观测 | 判定 |
|---|---|
| 各身份状态码与正文哈希完全一致 | `no_issue_found`（记录测过） |
| B-other 返回 401/403，A-self 200 | `ruled_out`（点名鉴权中间件） |
| B-other 200 且正文含 **B 的专属字段** | `confirmed`（candidate） |
| B-other 200 但正文 = 首页/SPA fallback | `not_applicable`（前端路由，不是数据） |
| B-other 200 但正文为空/`{}` | `open_proof_gap`（可能是软 404） |
| 只有长度差异、无专属字段 | `open_proof_gap`，不许直接报 |
| 列表接口返回条数不同 | 需再看**内容**，条数不同可能是分页 |

**专属字段（victim_marker）要求**：B 的邮箱、长 UserId、订单号、手机号后四位、地址、私有文件名。≥8 字符或含 `@`。**禁止**用 `200` / `ok` / `id` / `true` / `customer` 当 marker。

---

## 2. 标准流程

1. 建两个测试账号 A、B（不同邮箱、不同租户/组织，若支持）。
2. 各自创建 1~2 个对象，记下 A 的 id 与 B 的 id，以及 B 的专属字段。
3. 对每个接口，按矩阵发请求。**每次只改身份**，URL/参数/头保持一致。
4. 记录：`identity / method / path / status / length / body_sha256 / key_fields`。
5. 有差异 → 进 `src-triage` 六问；过 → `src-retest` 取证。
6. 每格结果写 `coverage_record`（surface × risk=idor/bfla × outcome）。

---

## 3. 漏测清单（不试完不许说 clean）

- [ ] 所有动词（GET/POST/PUT/PATCH），不只 GET
- [ ] 所有 ID 形态：数字、UUID、base64、hashid、slug、邮箱、手机号
- [ ] 数组/批量：`?ids=1,2`、`{"ids":[...]}`、GraphQL 批量
- [ ] 嵌套资源与子路由
- [ ] 版本前缀 v1/v2/v3（老版本常缺鉴权）
- [ ] 内部/移动端接口（`/api/internal`、`/api/mobile`）
- [ ] 导出/报表接口（`/export`、`/download`、`/report`）
- [ ] 文件/附件直链（对象存储 URL 是否可换 key）
- [ ] 软删除对象（`?include_deleted=true`）
- [ ] 头覆盖：`X-Original-URL`、`X-Rewrite-URL`、`X-Forwarded-For` 伪造内网

---

## 4. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 200 但正文是登录页/首页 | SPA fallback |
| 200 但返回的是**自己的**数据 | token 没换成功 |
| 列表条数不同 | 分页/权限过滤正常 |
| 公开资料（昵称、头像）可见 | 无安全边界 |
| 只有 403 变成 200，正文是错误 JSON | 软 404 |
| 用 admin token 测出来的「越权」 | 管理员本来就该能看 |

---

## 5. 定级

| 证据 | 建议 |
|---|---|
| 读到自己无权访问的**他人 PII** | High |
| 读到他人订单/支付/发票 | High~Critical |
| 低权限执行管理员动作（BFLA） | High~Critical |
| 仅读到非敏感公开字段 | Low / informational |
| 仅状态码差异、无数据 | 不报，记 `open_proof_gap` |

---

## 6. 工具对照

| 目的 | 工具 |
|---|---|
| 记录单次请求与响应 | `http_evidence_record` |
| attack vs control 字段级对照 | `http_evidence_compare` |
| 浏览器内验证（前端路由/GraphQL） | browser 工具 / `browser_evaluate` |
| 台账 | `coverage_record`（risk=`idor` / `bfla`） |
| 复测 | `src-retest`（必须带 `control-self`） |

未挂载证据工具时：用 curl 保存原始请求/响应到任务工作目录，**不要只把输出粘进 Markdown**，并在报告里注明采集方式。

---

## 7. 报告要点

- 矩阵表：身份 × 接口 × 状态码 × 关键字段
- 明确写出 `control-self` 结果（A 读自己 200，A 读 B 也 200）
- victim_marker 原文（脱敏后）
- 影响：能读到哪类数据、影响多少用户（按接口暴露面估计，不夸大）
- 修复：对象级授权校验（不是只在前端隐藏）
