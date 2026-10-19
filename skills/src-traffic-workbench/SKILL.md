---
name: src-traffic-workbench
description: 多身份差分重放与证据工作台：把「A 能读 B 的数据」这类断言变成可机器核对的对照实验（匿名/A/B/低权/管理员 同请求重放，落独立证据包 + sha256 + 差分表）。覆盖 IDOR/BOLA/BFLA、越权、缓存/头注入对照、replay 复现。当要确认一个越权候选、准备 report_finding、或复测时使用。
---
# src-traffic-workbench — 差分重放与证据工作台

## 要解决的问题

SRC 报告被退回的头号原因不是「洞不存在」，是**「无法复现 / 证据不足」**。
典型坏证据：

- 「我用 A 的 token 请求了 B 的 ID，返回 200」→ 200 不代表拿到了 B 的数据（可能返回的是 A 自己的）。
- 「换 ID 后响应长度不同」→ 长度不同可能是错误页。
- 「匿名也能访问」→ 可能那个接口本来就公开。

**好证据 = 同一请求 × 多身份 × 可机器比对的差异 + 内容归属证明。**

## 核心工具：`diff_replay`

```python
diff_replay(
  outdir="/app/data/evidence/finding-<id>",
  url="https://api.target.com/v1/users/1002",
  method="GET",
  identity=[
    "anon=",
    "a=Authorization: Bearer <A的token>",
    "b=Authorization: Bearer <B的token>",
  ],
  json_path="email",
  expect_owner="b",
)
```

输出三态（与 `src-closure` 对齐）：

| verdict | 含义 | 下一步 |
|---|---|---|
| `possible_bola` | 非所有者拿到与所有者**完全相同**的正文 | 还必须人工确认「这份内容确实属于 B」+ 该接口设计上应鉴权 → 才能 confirmed |
| `ruled_out` | 非所有者没拿到所有者内容 | 记 `coverage_record(outcome=ruled_out, evidence=...)`，不要硬报 |
| `open_proof_gap` | 身份没跑成功 / 无法判定 | 补身份或补路径，**不得**写 confirmed |

## 标准动作

### 1. BOLA / IDOR（对象级）

1. 用**所有者**身份请求自己的对象，记录。
2. 用**另一个同权限用户**身份请求同一对象 ID。
3. 用**匿名**身份请求同一 ID。
4. 看 `json_path` 是否真的取到了所有者的字段（如 `email`）。
5. 若三者都能拿到同一份 → 再看是否本来就公开（对比无鉴权设计文档/前端是否也用同一接口）。

**反例（必须排除）**：
- 接口返回的是「当前登录用户」而不是 URL 里的 ID（那就不是 IDOR，是设计如此）。
- 返回 200 但 body 是 `{"error": ...}`。
- 对象 ID 是可枚举的公开资源（商品、文章）。

### 2. BFLA（功能级）

同一功能端点（如 `POST /admin/export`），用低权限身份请求，看是否 2xx 且产生副作用。
副作用必须**可观测且可逆**（例如导出任务被创建），不要真的删数据。

### 3. 缓存 / 头注入对照

- attack：带 `X-Forwarded-Host: evil.com` 的请求
- control：不带该头的相同请求
- 两次都带**同一个 cache buster**（如 `?cb=<随机>`），否则会命中别人的缓存。
- 比较响应体里的绝对 URL / 链接是否被污染。

### 4. replay 复现

报告里必须能给出「按顺序重放这三条请求即可复现」。用 `http_evidence_record` 逐条落包，`http_evidence_summary` 汇总。

## 证据包结构（必须保持）

```
/app/data/evidence/finding-<id>/
  pack.json              # 聚合：cases[] + sha256 + seal
  pack.seal.json         # HMAC 封印（report_check 会校验）
  cases/<name>/
    request.txt          # 原始请求（Authorization 已脱敏）
    response_headers.txt
    response.body
    meta.json            # status/body_len/body_sha256/checks
    seal.json
  diff-<ts>.json         # diff_replay 生成的差分表
```

`report_check` 会核对报告 `Evidence Binding` 里引用的 sha256 是否真在 `pack.json` 中。
**不要手抄 sha256**，从 `pack.json` / `diff-*.json` 复制。

## 铁律

1. **永远不要只用 200 当证据。** 必须给出内容归属或副作用。
2. **对照组必须存在**：至少一个「不该成功」的身份或一次「不带 payload」的请求。
3. **不要用真实用户的数据**。测试对象必须是你自己创建的账号/对象；若必须用他人对象，只看能否读到，**不得导出、不得留存**。
4. **敏感头自动脱敏**是 recorder 做的，不要试图绕过或改回去。
5. `open_proof_gap` 是合法结论，`confirmed` 不是唯一目标。把它写进 `src-closure` 的三态。

## 与其他 skill 的关系

- 上游：`src-taxonomy`（该测什么）→ `src-coverage`（测了没）
- 本 skill：产出可核对证据
- 下游：`src-closure`（三态收敛）→ `src-report-writing` + `report_check`（提交门禁）
