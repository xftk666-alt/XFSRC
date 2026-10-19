---
name: src-scope-guard
description: 海外 SRC 授权范围内的发请求前范围闸门。任何请求（含 curl、httpx、浏览器、工具扫描）发出前，必须先确认目标 host 在 task_scope 内；task_scope 为空一律按 out-of-scope 处理。用于 HackerOne/Bugcrowd/Intigriti 等赏金 program，避免 out-of-scope 请求导致封号。当任务刚创建、拿到新资产、或要跑任何主动工具时使用。
---
# src-scope-guard — 发请求前的授权边界闸门

## 为什么这条最重要

三家平台封号的**第一原因不是误报，是 out-of-scope 请求**。
误报最多是「报告被拒」，out-of-scope 是「账号被封 + program 拉黑」。

所以这条闸门的目标很单一：**在请求发出之前，就能回答「这个 host 在不在授权范围内」。**

## 铁律

1. **`task_scope` 表是授权边界的唯一事实来源。** 不是 SKILL.md 里写的 URL，不是用户口头说的域名，不是资产库里有的资产。
2. **`task_scope` 为空 = 没有任何授权 = 全部禁止。** fail closed，不是 fail open。
3. **`unknown` 按 `out-of-scope` 处理。** 拿不准就停手问人，不要「先试一下」。
4. **子域不等于根域授权。** 除非 scope 条目是 `root_domain` / 通配，否则 `a.example.com` 不等于 `example.com`。
5. **资产库里有 ≠ 授权范围内。** 资产库是「发现过什么」，scope 是「允许测什么」。

## 开工前 5 步检查表

任何请求发出前，逐条打勾：

- [ ] **1. 目标 host 已解析**：知道确切 host（不是「那个站」），且是 FQDN 或 IP。
- [ ] **2. 查 scope**：
      ```bash
      python3 /app/skills/src-retest/scripts/scope_check.py --task-id <id> --url <url>
      ```
      或 `--host <host>`。
- [ ] **3. 读到 `in-scope` 才继续**。`out-of-scope` → 停手。`unknown`（scope 为空）→ 停手，先补 scope。
- [ ] **4. 确认 program 政策**：主动扫描是否允许？自动化是否要申报？速率限制？禁止的 payload 类型（如真实数据导出）？
- [ ] **5. 确认这次请求属于「已授权的最小验证」**，不是「顺手扫一下」。

## 常见越界陷阱（都会导致封号）

| 陷阱 | 后果 | 正确做法 |
|---|---|---|
| 扫 `example.com` 时顺手扫了 `example-cdn.net` | 第三方 CDN 不在 scope | 逐个 host 查 scope |
| 用 `subfinder` 枚举出 300 个子域后全量跑 nuclei | 其中大量不在 scope | 枚举可以做，**请求前逐个过滤** |
| 看到 CNAME 指向 S3/Heroku 就去验证接管 | 目标域不在 scope 或厂商不受理 | 先查 scope，再查 program 是否受理 takeover |
| OOB 域名用了公共 interactsh | 部分 program 明确禁止公共 OOB | 用自建 OOB（`oob_gen`） |
| 测试时用真实用户账号 | 直接封号 | 只用自己的测试账号 |
| 拿靶场洞去交 | 判无效提交 | 见 `src-closure` 的靶场识别 |

## 与靶场识别的配合

`scope_check` 回答「是否授权」；`lab_detect` 回答「是否靶场」。

**两个都要过**：

- scope 不通过 → 不发请求
- lab 判定为靶场 → 可以测，但**永远不能提交**（`submit_brief` 会强制 `do-not-submit`）

靶场识别已扩展到：RFC1918 全段（10./172.16-31./192.168.）、`169.254.`、TEST-NET、`.local` / `.internal` / `.test` / `.example` / `.htb` / `.corp`、单标签主机名、已知靶场标识词（juice-shop / dvwa / bwapp / webgoat / vulnhub / HTB / THM…）。

```python
# 平台里注册成了只读工具，直接调用（支持 0177.0.0.1 / 2130706433 等变体）
lab_detect(host="10.10.10.5")          # lab=true, reasons=["ip 10.10.10.5 属于非公网网段 10.0.0.0/8"]
lab_detect(host="portal.mybank.com")   # lab=false → 看起来是真实资产
lab_detect(pack="/app/data/evidence/finding-6/pack.json")  # 整包判定
```

> 注意：`lab_detect` 只回答「是不是靶场」，**不做放行决定**。
> 最终能否提交仍由 `report_check` / `evidence_gate` 独立复判——
> 即使你在 evidence 里写 `lab: false`，它们也会自己再判一次并拦下。

## scope 怎么登记

用平台的 `add_task_scope` 工具，或在任务创建时写进 goal。一行一条：

```
example.com                 # 根域，含子域
api.example.com             # 单子域
10.0.0.0/24                 # 网段
203.0.113.10                # 单 IP
```

**deny 也要写**：program 的 out-of-scope 列表（如 `status.example.com`、`blog.example.com`）要显式登记，避免误测。

## 失败时的正确反应

`scope_check` 返回 out-of-scope 时：

1. **不要**换个写法再试（`http://` 换 `https://`、加端口、用 IP 代替域名）。
2. **不要**认为「scope 没登记所以是漏登记」。
3. 停下来，向用户确认：这个 host 是否真的在 program scope 内？拿到确认后再补 `task_scope`。

## 与其它 skill 的关系

- 开工前：`src-onboarding`（选 program）→ `src-platform-scope`（拉 scope）→ **本 skill**（逐 host 校验）
- 侦察时：`overseas-src-recon` 的每一步请求前都过本 skill
- 上报前：`src-closure`（收敛）→ `src-triage`（判重）→ `src-retest`（证据门禁）
