---
name: src-onboarding
description: 海外 SRC 开工前选 program、读公开范围、合规红线与练习路径。当用户还没平台账号、只想浏览公开 bounty 范围、或准备加入 H1/Bugcrowd/Intigriti 某个 program 时使用。明确：公开范围 ≠ 授权，未加入 program 禁止对真实资产发任何请求。
---
# 海外 SRC 开工（无账号也能读范围，有账号才能测）

配套：`src-platform-scope`（有 token 后拉官方 scope）→ `overseas-src-recon`（授权后侦察）→ 各漏洞技能 → **`src-triage`（是不是洞）** → `src-retest` → **`src-hunter-brief`（给猎人一页交/不交）** → `src-report-writing`。

猎人若声明「我不会复测，提交我自己点」：让他在漏洞详情点「漏洞复测」；独立会话跑完看卡片。Auto 不在聊天里打。

---

## 0. 铁律

- **公开范围 dump ≠ 授权。** `public_src_programs` 只帮助你挑 program、看大概有哪些资产。
- **未加入 / 未被接受 / 未读完 policy，禁止对真实资产发任何请求**（包括 httpx、subfinder 对他人域名、nuclei、浏览器打开目标）。
- 现在没有 H1/Bugcrowd/Intigriti 账号时：**只允许**读公开数据、在**本平台授权靶场**（Juice Shop）上练手。
- 不确定就停。越界 = 封号 + 法律风险。

---

## 1. 还没账号时你能做的

1. 用 `public_src_programs` 浏览公开 program（数据源：arkadiyt/bounty-targets-data，有缓存）。
2. 记下候选 handle、in-scope 类型（WILDCARD / URL / API / SOURCE_CODE / APP）、是否付奖金。
3. 去官网注册（人操作，平台代不了）：
   - HackerOne → `/settings/api_token`
   - Bugcrowd → `tracker.bugcrowd.com/user/api_credentials`（IPv4）
   - Intigriti → Personal Access Token
4. 在本环境练：`http://juice-shop:3000`（容器内网；**httpx 不读 /etc/hosts 的版本优先 `http://172.18.0.3:3000`**）。访问内网必须绕过全局代理（`curl --noproxy '*'`）；`httpx_probe` 已按目标自动分流，混打内网+公网也不会再 502。

```
public_src_programs(platform="h1", query="shop", limit=8)
public_src_programs(platform="h1", handle="security")
public_src_programs(platform="bugcrowd", query="public")
public_src_programs(platform="intigriti", query="web")
```

输出带 `disclaimer`。**禁止**把 listed in-scope 当成可以开始扫描的目标。

---

## 2. 怎么挑第一个 program（新手）

优先同时满足：

| 条件 | 原因 |
|---|---|
| `offers_bounties=true` 或明确 VDP 你可接受 | VDP 无奖金，练手可以、养家不行 |
| `submission_state=open` | 已关闭的不要看 |
| in-scope 是具体 URL / 少量 WILDCARD | `*.corp.com` 过大，新手易越界 |
| 有 Web 应用，不是只收 Android/IoT/源码 | 本平台强项是 Web |
| 响应天数不是两位数起步 | 否则报告石沉大海 |
| policy **允许自建测试账号** | 后面测 IDOR/Auth 必须有 |

避开：加密货币热钱包、政府、明确 **禁止一切自动化** 且资产极大的项目（第一个不要选这个）。

Intigriti 对 **公共 OOB / 主动扫描** 普遍更严；本平台 OOB 是自建 `oob.aiboli.top`，仍以该 program policy 为准。

---

## 3. 有账号之后（才允许碰真实目标）

```
加入 program（网页）→ 等 accepted
→ src-platform-scope：h1_scope / bugcrowd_scope / intigriti_scope
→ 逐条勾合规清单（扫描? OOB? 多账号?）
→ add_company_scope 登记公司+in-scope
→ overseas-src-recon（被动优先）
→ api-recon / src-idor / src-xss / src-auth / src-ssrf / src-takeover / src-info-disclosure / src-business-logic / src-graphql
→ src-triage（drop 则不开洞）
→ report_finding 仅限 candidate
→ src-retest（not_a_vuln 则不交）
→ src-report-writing
```

没有 token 时 **不要**调用 `h1_scope` / `bugcrowd_scope` / `intigriti_scope`（必 401）。

---

## 4. 本平台工具对照

| 目的 | 工具 |
|---|---|
| 公开 program/范围摘要 | `public_src_programs` |
| 官方 scope（需 token） | `h1_scope` `bugcrowd_scope` `intigriti_scope` |
| 证书透明度子域（被动，仍须已授权域名） | `crtsh_enum` |
| 浏览器（登录/点功能/截图） | `browser` MCP |
| 练习靶场 | Juice Shop `http://172.18.0.3:3000` |

---

## 5. Agent 行为

- 用户说「帮我挖 XXX.com / 这个 H1 program」但**没有声明已加入**：只给公开摘要 + 注册/加入步骤，**不探测该域名**。
- 用户明确「只在 Juice Shop / 本任务授权范围内练」：可以测。
- 永远先读 scope 技能，再侦察技能。
