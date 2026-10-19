---
name: src-idor
description: 海外 SRC 授权范围内的 IDOR/越权（BOLA/BFLA/水平/垂直）测试标准流程。当已拿到登录态或 API 清单、需要测对象级/功能级越权、或核对 H1/Bugcrowd/Intigriti 对 IDOR 的报告要求时使用。含发现对象、换 ID 对照、多账号验证、常见误报与定级。
---
# 海外 SRC：IDOR / 越权（BOLA / BFLA）

面向 **已授权** program 的 in-scope API/页面。目标：用**最少请求**确认「用户 A 能否读写用户 B 的对象 / 低权限能否调高权限功能」。

配套：`src-platform-scope`（先确认允许测越权、允许多账号）→ 本技能 → **`src-triage`（公开对象 / 只看到 200 不是洞）** → `src-retest` → `src-report-writing`。

---

## 0. 开工前（缺一不可）

- [ ] 目标在 in-scope；**不确定就停**
- [ ] program 允许：**多账号 / 越权测试 / 访问他人资源**（多数允许；仍以 policy 为准）
- [ ] **自建测试账号**，禁止用真实用户数据
- [ ] 不要爆破 ID（高频遍历会被当 DoS）。先换 1～3 个已知 ID 对照
- [ ] 先被动收集接口（`api-recon` / `katana_crawl` / `gau_urls`），再针对测，不要无脑扫全站

> 越界、打真实用户、大量遍历对象 ID = 拒收 / 封号。

---

## 1. 先搞清测的是哪一种

| 类型 | 含义 | 典型 |
|---|---|---|
| **水平 IDOR (BOLA)** | 同角色，访问**别人的对象** | `GET /api/orders/1002` 用 A 的 token 读到 B 的订单 |
| **垂直越权 (BFLA)** | 低权限调用**高权限功能** | 普通用户 `DELETE /api/admin/users/1` |
| **未授权访问** | 完全不带 cookie/token 也能读 | 去掉 `Authorization` 仍 200 |
| **批量/导出越权** | 列表、导出、搜索没有按用户过滤 | `/api/users?limit=100` 返回全站用户 |

海外 SRC 里 **BOLA 最常见、最好过审**，证据也最好写。

---

## 2. 发现「带对象 ID 的接口」（比乱扫重要）

从已授权目标的流量/JS/历史 URL 里找这类参数（名称不限）：

`id` `user_id` `uid` `account_id` `order_id` `uuid` `guid` `document_id` `file_id` `invoice` `booking` `patient` `org_id` `tenant`

做法：

1. `katana_crawl(url="<in-scope>")` 或 `gau_urls` / `waybackurls_urls` 拿 URL 列表，写入文件
2. `gf_filter(file="<urls.txt>", pattern="urls")` 清洗
3. 参数爆破仅在 **policy 允许** 时：  
   `ffuf_fuzz(url="https://in-scope/api/item?FUZZ=1", wordlist="/usr/local/share/wordlists/burp-parameter-names.txt")`  
   **限速、单接口、不要全站**
4. 浏览器 MCP 登录后点一遍「我的订单/资料/文件」，从捕获请求里抄真实 path + id

**UUID 不是免死金牌**：把 A 的 UUID 换成 B 的（从邀请链接、导出、邮件、对象列表泄漏里拿），一样能测。

---

## 3. 最小验证（必须对照，禁止只改一次碰运气）

准备：**账号 A、账号 B**（同角色），可选：**低权限 C、管理员 D**（仅当 policy 允许且都是你自己的测试号）。

对**每一个**候选接口做这张表（复制到笔记）：

| 步骤 | 请求 | 期望安全行为 | 若出现则可能有洞 |
|---|---|---|---|
| 1. 正主 | A 的 token + **A 的 object_id** | 200 + A 的数据 | — |
| 2. 水平 | A 的 token + **B 的 object_id** | 401/403/404 | **200 且是 B 的数据** → BOLA |
| 3. 未授权 | **无 token** + B 的 object_id | 401/403 | 200 → 未授权访问（另报或合并说明） |
| 4. 方法 | 对同一资源试 `GET/PUT/PATCH/DELETE`（**不要真删生产数据**；无影响环境才测写） | 写操作被拒 | 能改/删 B 的对象 → 更高危 |
| 5. 垂直 | C 的 token 调仅 D 能用的 path | 403 | 200 → BFLA |

**判定铁则**：

- 必须看到 **B 的专属字段**（邮箱、订单金额、姓名），不能只看状态码 200（空对象/通用错误页是误报）
- 两次请求的 **token 只换一次变量**（只换 id 或只去掉 token），方便写复现
- 列表接口：A 的 token 调 `/api/orders` 若混进 B 的记录 → 同样是 IDOR

**禁止**：把 id 从 1 扫到 100000；对支付/删除点「试着提交」造成真实资金或数据破坏。

---

## 4. 常见绕过（仅对已确认对象、少量尝试）

接口看起来 403 时，**不要放弃也不要爆破**，按 policy 允许的前提下逐条试 **一次**：

- 改方法：`GET` 禁了试 `POST`/`PUT`；或 `_method=PUT`
- 改 Content-Type：`application/json` ↔ `form`
- 二次绑定：body 里同时带 `user_id=A` 和 path 里 `id=B`（服务端只校验了前者）
- 编码：`id=B` vs `id[]=B` vs JSON `{"id": B}`
- 版本：`/api/v1/` 挡了试 `/api/v2/`、`/internal/`、移动端 host（仍须 in-scope）
- ID 预测：若是自增整数且 B 的 id 刚好比 A 大 1（注册顺序），换邻号 **1～2 次**即可，禁止遍历

试完仍 403 → 记「该接口有对象级校验」，换下一个接口。

---

## 5. 定级（给 `src-report-writing` 用，勿虚高）

| 实际影响 | 建议 |
|---|---|
| 读到他人 PII / 订单 / 文件 / 消息 | Medium～High（看数据敏感度） |
| 能改他人资料、改绑定邮箱、改收货地址 | High |
| 能接管账户 / 改密码 / 删他人资源 | High～Critical |
| 仅公开或自己也能在 UI 看到的字段 | 常被拒或 Informational，不要报 |

HackerOne 常见 weakness：`Improper Access Control` / `Insecure Direct Object Reference (IDOR)`。  
Bugcrowd 对号 **VRT → Broken Access Control (IDOR)**。

---

## 6. 证据清单（不够就不要报）

- 账号 A/B 如何注册（测试号）
- 完整 HTTP：A 读自己、A 读 B，**响应里能看出是 B 的数据**（打码真实 PII）
- 必须用 `http_evidence_record` 记 attack（A+B的id）与 control（A+自己的id、无 token），再用 `http_evidence_compare`；见 `src-retest`
- object_id 从哪来（响应、邀请链接、自增）
- 未造成数据破坏的说明

然后 `src-triage`（过不了六问不要 `report_finding`）→ `src-retest` → `src-report-writing`。

---

## 7. 本平台工具对照

| 目的 | 工具 |
|---|---|
| 发现 URL/参数 | `katana_crawl` `gau_urls` `waybackurls_urls` `gf_filter` |
| 补隐藏参数（需允许 fuzz） | `ffuf_fuzz` + `burp-parameter-names.txt` |
| 浏览器点功能抓包 | `browser` MCP |
| 登记漏洞 | `report_finding`（vulnclass 用 `idor` 或 `broken-access-control`） |
| 写报告 | 技能 `src-report-writing` |

**不要用** `sqlmap_scan` / `dalfox_xss` / `naabu` 来「找 IDOR」——类型不对，还容易违规。
