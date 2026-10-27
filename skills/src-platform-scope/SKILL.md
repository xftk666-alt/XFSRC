---
name: src-platform-scope
description: 海外 SRC 三大平台（HackerOne / Bugcrowd / Intigriti）的 program 范围(scope)获取与合规要点。当需要拉取某个授权 program 的 in-scope/out-of-scope 资产、确认自动化政策、决定用哪些工具、或核对 token/API 时使用。内置三平台 API 端点、认证方式、政策差异与开工前合规清单。
---
# 海外 SRC 平台范围获取（HackerOne / Bugcrowd / Intigriti）

面向这三家的**授权** program，解决一件事：**动手前把范围（scope）和政策拿准**。

---

## 0. 铁律：先 scope，后动手

- **in-scope 才可碰**；out-of-scope（第三方、营销站、blog、状态页、母公司资产）一律不碰。
- **不确定是否 in-scope，就当 out-of-scope 处理**。
- 遵守 program 的**自动化政策**与**速率限制**；越界 = 封号 + 丧失奖金 + 法律风险。
- **还没有三平台账号时**：用 `src-onboarding` + `public_src_programs` 只读公开 dump。公开范围 **不是** 授权，禁止对 dump 里的资产发探测。
- 有 token 后再用下面的 `h1_scope` / `bugcrowd_scope` / `intigriti_scope`。

---

## 1. 三平台政策差异速查

| 维度 | HackerOne | Bugcrowd | Intigriti |
|---|---|---|---|
| 范围叫法 | Structured Scopes | Scope / Targets | In-scope assets |
| 政策粒度 | 逐 program | 逐 program | 逐 program |
| 自动化限制 | 多数 program **禁止主动扫描/fuzz** | 部分禁止 | **普遍偏严**，很多只允许被动 |
| OOB（带外） | 需看 program 是否允许 | 需看 program | 多数**禁止**使用外部 OOB 服务 |
| 报告语言 | 英文 | 英文 | 英文 |
| 复现要求 | 清晰步骤 + 影响 | 步骤 + 影响 + CVSS | 步骤 + 影响 |
| API 认证 | Basic（用户名:Token） | Token（`Token key:secret`） | Bearer Token |
| API 限速 | 读 600/min | 60/min/IP | 见 program |

> 每家都必须在**该 program 的 policy 页面**逐条确认：能否自动扫描、能否用 OOB、能否多账号、报告格式。**不要用一家经验套另一家。**

---

## 2. 获取范围（API）

### 2.1 HackerOne

- Web：`https://hackerone.com/<handle>` → Policy / Scope 页。
- Token：`https://hackerone.com/settings/api_token` 生成，得到 **用户名 + API Token**。
- API（HTTP Basic，`-u username:token`）：
  - 我参与的 program 列表：`GET /v1/hackers/programs`
  - **结构化范围**：`GET /v1/hackers/programs/{handle}/structured_scopes` ← 拿 in/out-of-scope 资产
  - 范围排除项：`GET /v1/hackers/programs/{handle}/scope_exclusions`
  - 弱点类型：`GET /v1/hackers/programs/{handle}/weaknesses`
- **平台工具**：`h1_scope(handle="<handle>", username="<用户名>", token="<token>")`
- 限速：读 600/min；`structured_scopes` 50/min。

### 2.2 Bugcrowd

- Web：`https://bugcrowd.com/<handle>` → Scope 页。
- Token：`https://tracker.bugcrowd.com/user/api_credentials`（**仅 IPv4**，可设 IP 白名单）。
- API（请求头 `Authorization: Token <token>` 且 `Accept: application/vnd.bugcrowd+json`）：
  - 我参与的 program：`GET /programs`
  - 单个 program（含 targets/scope）：`GET /programs/{handle}`
- **平台工具**：`bugcrowd_scope(handle="<handle>", token="<token>")`
- 限速：60 请求/分钟/IP。

### 2.3 Intigriti

- Web：`https://app.intigriti.com/programs/<company>/<program>/detail`。
- Token：登录后在账号/个人设置里生成 Personal Access Token。
- API（`Authorization: Bearer <token>`）：
  - 我的 program 列表：`GET https://api.intigriti.com/external/researcher/v1/programs`
  - 单个 program 详情（含 in-scope）：`GET .../programs/{programId}`
- **平台工具**：`intigriti_scope(program_id="<id>", token="<token>")`
- ⚠️ **已知坑**：文档站 `docs.intigriti.com` 在部分网络**不可达（EOF）**，但 **API 正常**。不要因为打不开文档就以为 API 不能用。

---

## 3. 开工前合规清单（每个 program 逐项打勾）

- [ ] **in-scope 资产**：域名 / 子域 / IP / 移动端 / API / 代码仓库
- [ ] **out-of-scope 清单**：第三方、营销站、状态页、母公司资产
- [ ] **是否允许主动扫描 / fuzz**（禁止则只做被动收集）
- [ ] **速率限制**（限速，避免被判 DoS）
- [ ] **是否允许 OOB**（interactsh / 自建域名）
  - 本平台已部署**自建 OOB 服务器**（`oob.aiboli.top`，interactsh 1.4.1）。工具：`oob_gen` / `oob_poll`。
  - ✅ **自建 OOB 通常可绕开「禁止公共 OOB 服务」的限制**——很多 program 禁的是公共/第三方 OOB（怕数据外泄给第三方），自建在你自己的域名下，多数允许。**但仍以该 program policy 为准。**
- [ ] **是否允许测试账号 / 多账号 / 越权测试**
- [ ] **报告语言与格式**（见 `src-report-writing` 技能）
- [ ] **是否允许自动化工具**（nuclei/ffuf 等，很多 program 明确禁止）

> 把结论写下来，再决定用 `overseas-src-recon` 里的哪些步骤。

---

## 4. 登记与隔离

- 用 `add_company_scope` 把 **program 公司名 + in-scope 域名/IP** 加入范围（域名/网络会**自动认领**命中的资产）。
- 用 `insert_assets` 登记发现的资产。
- **不同 program 的资产分开归属**，不要混（避免 A 的资产被当成 B 的 scope 去测）。

---

## 5. 一句话流程

```
确认 program 政策(网页) → 拉 scope(API: h1_scope / bugcrowd_scope / intigriti_scope)
→ 登记 in-scope 到公司范围(add_company_scope) → 再交给 overseas-src-recon 做侦察
→ 手工测试（各 src-*）→ src-triage → src-retest → src-report-writing
```
