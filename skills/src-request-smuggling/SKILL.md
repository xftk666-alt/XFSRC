---
name: src-request-smuggling
description: 海外 SRC 授权范围内的 HTTP 请求走私/desync 测试。覆盖 CL.TE、TE.CL、TE.TE 混淆、CL.CL、H2.CL/H2.TE 与 HTTP/2 降级。强调必须用 pipelining 对照与重定向回显对照排除误报，且只在明确允许的 program 做最小验证。当目标位于 CDN/反代/负载均衡之后时使用。
---
# src-request-smuggling — HTTP 请求走私 / desync

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明前端与后端对请求边界解析不一致（desync），并给出**可复现的差分证据**。这是自动化误报率最高的类目之一，本技能的核心是**先排除误报，再谈利用**。

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线（最高风险类目）

- [ ] **只在 program 明确允许** request smuggling / desync 测试时做；policy 未提 → 先问，不要默认允许
- [ ] 禁止对共享生产缓存/共享连接做**持续性投毒**。验证到「第二个请求被污染」即停
- [ ] 禁止把真实用户当受害者：只用**自己的第二个连接/第二个测试账号**验证跨连接影响
- [ ] 禁止 DoS 型 payload（超大 chunk、无限连接占用）
- [ ] 单目标探测 ≤ 20 个请求；命中后立即停并记录
- [ ] 若前端直接 400/405 拒绝且不传播 → **不是洞**，停止

---

## 1. 先判断架构

```bash
curl -s -I "https://in-scope.example.com/" | grep -iE \
  "(server|via|x-served-by|x-cache|cf-ray|x-amz|x-varnish|akamai)"
curl -s -I --http1.1 "https://in-scope.example.com/" | head -1
curl -s -I --http2   "https://in-scope.example.com/" | head -1
```

典型链：Cloudflare/Akamai/ALB → Nginx/HAProxy → 应用。**只有多级 HTTP 处理器才可能 desync**；单层直连基本不用测。

---

## 2. 必测变体（不试完不许说 clean）

| 变体 | 要点 |
|---|---|
| CL.TE | 前端信 `Content-Length`，后端信 `Transfer-Encoding: chunked` |
| TE.CL | 反之 |
| TE.TE | 混淆 TE：`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`、冒号前空格/制表符、重复 TE、`chunked, identity`、chunk 长度前导空格 |
| CL.CL | 两个 `Content-Length`，一方取第一个、一方取最后一个 |
| H2.CL / H2.TE | HTTP/2 前端接受，降级到 HTTP/1.1 源站 |
| H2 CRLF | 头名/头值注入 CRLF |
| 路由差异 | WAF 规范化可能只在 `/` 掩盖，换深层路径再试 |

---

## 3. 确认判据（缺一不可）

**正面信号必须是 desync，不是单次 200。**

### 3.1 必做的两个对照

**Control 1 — pipelining 排除（必做）**
把同样的两个请求**去掉所有 CL/TE 走私头**，做成两个普通 pipelined GET。如果**仍然**收到两个响应 → 之前看到的「两个响应」只是 HTTP/1.1 pipelining，**不是走私**。

**Control 2 — 重定向回显排除（必做）**
发一个普通 `GET /<唯一canary>`，不带任何走私头。如果 canary 出现在 `Location` 或正文 → 说明只是重定向引擎回显，**canary 不能当走私证据**。

### 3.2 至少一个真差分

- **时间差分**：不完整 chunk / 长度不匹配的探测挂起 ~5–10s，**而相同基线请求瞬间返回**（两个时间都要记录）
- **跨连接污染**：走私后，在**另一条连接**上的正常请求被污染：返回了你没请求的端点、收到 400/405、被延迟、或收到你注入的前缀
- **同连接 socket 复用**：攻击请求后立刻在同连接发正常请求，与全新连接的同一请求做 diff

### 3.3 明确不算证据

| 现象 | 为什么不算 |
|---|---|
| 单请求返回 200 | 什么也没证明 |
| 一条连接上收到两个响应 | 普通 pipelining |
| `Location` 里出现你的 canary | 重定向回显 |
| 重定向上的 `X-Cache: HIT` | 重定向本来就可缓存 |
| 单请求挂起 ~10s | 多半是 keep-alive idle timeout |
| 前端返回 400/405 | desync 未传播 |

---

## 4. 最小验证流程

1. 架构确认（第 1 节）。
2. 基线：同一路径正常请求的**耗时与响应哈希**。
3. 逐个变体发**一次**探测，记录耗时与响应。
4. 有挂起 → 立即做 Control 1/2，再复测一次确认可重复。
5. 跨连接验证：用第二条连接（或第二个测试账号）发正常请求，看是否被污染。
6. 命中即停。保存原始字节（`xxd`/`--trace-ascii`）到证据目录。
7. 进 `src-triage`；`confirmed` 才写报告。

> 原始 socket 证据无法用普通 HTTP 证据工具完整封印时，保存 `request.raw` / `response.raw` + `sha256` + 采集命令与时间，并在报告中说明采集方式。**禁止**只贴一段文字结论。

---

## 5. 误报/漏报清单

**误报**
- 把 pipelining 当走私
- 把重定向回显当走私
- 把 keep-alive 超时当 desync
- 把 WAF 拦截页当后端异常
- 把单次网络抖动当时间差分（必须可重复 ≥2 次）

**漏报**
- 只测 `/`，没测深层路径
- 只测 GET，没测 POST
- 只测 CL.TE，没测 TE.CL / TE.TE 混淆 / H2
- 没强制 keep-alive（`Connection: keep-alive`）
- 没换 HTTP 方法或 cache-busting 路径

---

## 6. 定级

| 证据 | 建议 |
|---|---|
| 仅时间差分，无可观测污染 | Medium（且需可重复） |
| 跨连接污染，可绕过前端访问控制 | High |
| 可捕获他人请求（含 Cookie/Authorization） | Critical |
| 可与缓存投毒组合影响所有用户 | Critical |
| 前端直接拒绝、不传播 | 不报 |

---

## 7. 工具对照

| 目的 | 工具 |
|---|---|
| 原始字节请求 | `curl --trace-ascii`、Python `socket`、Burp Repeater（关自动 CL） |
| 证据保存 | 任务工作目录 + sha256；有 `http_evidence_record` 时优先用它 |
| 台账 | `coverage_record`（risk=`http_request_smuggling`） |
| 复测 | `src-retest`（必须复现差分，不接受单次 200） |

---

## 8. 报告要点

- 架构图（前端/后端分别是什么）
- 变体类型（CL.TE / TE.CL / TE.TE / H2.*）
- 两个对照的结果（pipelining、重定向回显）
- 时间差分：攻击耗时 vs 基线耗时（各 ≥2 次）
- 跨连接污染的具体响应
- 影响：能绕过什么控制、能拿到什么
- 修复：前后端统一解析、拒绝同时带 CL+TE、端到端 HTTP/2、规范化
