---
name: src-ssrf
description: 海外 SRC 授权范围内的 SSRF（含盲 SSRF）测试与带外验证流程。当接口有 URL/回调/Webhook/文件抓取/PDF 生成等参数、或需要用自建 OOB 确认目标是否外连时使用。内置合规（公共 OOB 常被禁）、oob_gen/oob_poll 用法、误报排除与定级。
---
# 海外 SRC：SSRF（含盲 SSRF / 带外验证）

面向 **已授权** program 的 in-scope 功能：让服务器**替你发请求**（抓 URL、预览链接、导入、Webhook、PDF、头像拉取）。  
目标：用**自建 OOB** 证明服务器出网，再评估能否打到内网/云元数据——**禁止把 SSRF 当端口扫描器扫内网大段**。

配套：`src-platform-scope`（OOB 是否允许）→ 本技能 → **`src-triage`（客户端 follow 302 / 自己的 UA 打到 OOB = 不是洞）** → `src-retest` → `src-report-writing`。

---

## 0. 合规（海外 SRC 最容易在这里翻车）

- [ ] 目标 in-scope
- [ ] **是否允许 OOB / 带外**：payload 会打到 `oob.aiboli.top`（**自建**，不是公共 interactsh）
  - 很多 program **禁止公共 OOB**（数据到第三方）；**自建通常可过，仍以 policy 为准**
  - Intigriti 尤其要逐条看
- [ ] 是否允许测 SSRF、是否把「打内网/localhost」列为 out-of-scope
- [ ] **禁止**：用 SSRF 扫整个 RFC1918、打第三方、打云厂商控制面以外的无关主机
- [ ] 先 OOB 证明「会外连」，再考虑 **单次** 探测 `127.0.0.1` / 链路本地元数据；不要一上来扫 65535 端口

本平台 OOB：

- 域名：`*.oob.aiboli.top`（自建 interactsh 1.4.1）
- 工具：`oob_gen` → 把返回的 `OOB_DOMAIN` 塞进参数 → 等 5～10 秒 → `oob_poll`
- 漏扫（仅 policy 允许主动扫描时）：`nuclei_oob_scan`（已接同一台 OOB，勿用关了 interactsh 的 `nuclei_scan` 测盲洞）

---

## 1. 哪些功能像 SSRF（先找点，再发包）

| 功能 | 常见参数 |
|---|---|
| 链接预览 / 抓标题 / 发卡 | `url` `link` `src` `target` `uri` `dest` `path` |
| Webhook / 回调 | `callback` `webhook` `notify_url` `redirect_uri`（注意 open redirect 是另一类） |
| 头像/导入/PDF | `avatar` `file_url` `pdf` `template` `fetch` |
| 图片处理 / 代理 | `image` `proxy` `load` |

收集：

```
katana_crawl / gau_urls / waybackurls_urls
gf_filter(file=urls.txt, pattern=urls)
```

参数名可用（**允许 fuzz 时、单接口、限速**）：

```
ffuf_fuzz(url="https://in-scope/api/preview?FUZZ=http://example.com", wordlist="/usr/local/share/wordlists/burp-parameter-names.txt")
```

有回显（页面出现你指定 URL 的标题/正文）= **有回显 SSRF 候选**；没回显也要走 OOB（盲 SSRF）。

---

## 2. 标准验证顺序（少请求、可写进报告）

### 步骤 A — 生成专属 OOB

```
oob_gen()
```

记下 `OOB_DOMAIN`（形如 `xxxx.oob.aiboli.top`）和 `OOB_LOG`。  
**每次测试新域名**，避免和别人/上一轮串台。

### 步骤 B — 让目标去请求（只改一个参数）

把业务里原来的 URL 换成（优先 http，DNS 也会记）：

```
http://<OOB_DOMAIN>/src-ssrf
```

只对 **in-scope 接口** 发 **1 次**。不要循环重试打满日志。

### 步骤 C — 查回连

等 5～10 秒：

```
oob_poll(logfile="<OOB_LOG>")
```

- 有 `"protocol":"dns"` 或 `"protocol":"http"`，且 `unique-id` 对得上 → **服务器（或其解析链路）访问了你的域名**
- 只有 DNS 没有 HTTP：常见于出网被拦、只做了解析、或浏览器/WAF 预解析——**还不能直接写成「完整 SSRF」**
- 完全没有记录：参数没进服务端、异步队列很慢、或请求被客户端校验掉。可再等 30 秒 poll 一次；仍无则换接口，不要狂刷

### 步骤 D — 排除误报（必须做）

| 现象 | 可能不是 SSRF |
|---|---|
| 只有你本机/扫描器 IP 的访问 | 是 **你自己的浏览器或代理** 预取了 URL，不是目标服务器 |
| User-Agent 是 Chrome/你的工具 | 同上 |
| 回连来源 IP 是 Cloudflare/WAF | 可能是边缘节点，不一定是源站应用；写进报告说明来源 IP |
| 你把 URL 放进了会公开的字段，爬虫来抓 | 延迟很久才回连，慎报 |

**过关标准**：回连时间 ≈ 你点提交的时间；来源 IP 像目标机房/云；UA 像 Java/Go/Python/curl/okhttp，而不是你的浏览器。

#### D.1 协议分级（决定能写成什么）

| 回连协议 | 能证明什么 | 不能证明什么 |
|---|---|---|
| **HTTP**（有请求行/头/UA） | 目标服务器**主动发起了 HTTP 请求** | 还不能证明能读内网 |
| **DNS only**（无 HTTP） | 解析链路可达，**或**出网被拦、**或**预解析 | **不能**写成「完整 SSRF」，多数 program 判 Low/N/A |
| 无记录 | 参数未进服务端 / 异步慢 / 被校验 | 不能据此说「安全」 |

**只有 HTTP 回连才允许写 `confirmed SSRF`。DNS-only 必须写成 `open_proof_gap` 或 Low，并注明可能是解析器行为。**

#### D.2 明确不算 SSRF 的情况（机器会直接否）

- 回连 UA 是你的扫描器 / 浏览器 / curl 默认 UA（是你在访问，不是目标）
- 回连来源 IP 是你的出口 IP、本地代理、或 VPN 出口
- 目标只是**返回了一个 302 让你自己跳**（客户端跟随 = open redirect，不是 SSRF）
- 目标返回「URL 无效 / 无法访问」但你 OOB 有记录（可能是安全团队/沙箱在探测你）
- 只有一次、延迟数分钟的回连（爬虫/安全扫描器）

#### D.3 盲 RCE 与盲 SSRF 必须分开

- 证明「目标来抓了我的 URL」= **fetch 能力**，不是代码执行
- 盲 RCE 需要：**执行原语**（命令注入点）+ payload 中含**执行标记**（如 `; echo MARKER123` 的输出出现在响应/OOB 回连路径里）
- `RUNSCRIPT FROM`、XML 外部实体、webhook 回调**只能证明 fetch**，不能写成 RCE
- 无法给出执行标记 → 只能写 SSRF / XXE，不许写 RCE

### 步骤 E — 影响（policy 允许才做，每次一种、各 1 次）

不要扫网段。按 program 是否允许「localhost / 云元数据」：

1. `http://127.0.0.1:<已知产品文档里的端口>/`（如应用自己的 health，不要扫 1-65535）
2. 若目标在 AWS 且 policy 允许：`http://169.254.169.254/latest/meta-data/`（**读到 token/role 才算 High+**；只证明能打到链路本地也要写清楚实际内容）
3. 内网主机名仅当 **明确 in-scope**（例如 program 写了 `http://internal.example.local`）

打到第三方或乱扫内网 = 违规。

---

## 3. 绕过思路（每条最多试 1～2 个 payload，禁止字典爆破内网）

服务端若拦截 `127.0.0.1` / `169.254`：

- 十进制/短 IP、`127.1`、`0.0.0.0`、`[::1]`（看校验是否只挡了字符串）
- 域名再解析到 127.0.0.1（**你自己的 OOB 域名不要乱指**；可用公开的 `*.nip.io` 等，但先确认 program 允许）
- `http://127.0.0.1#@evil`、重定向（若跟随 302，OOB 先打你的域名再 302 到内网——**内网目标仍须 in-scope**）
- 换协议：`file:///` `gopher://` 多数现代库已关；不要对生产狂试 gopher 打 Redis

**gopher/file 造成的破坏性利用默认不做**，报告里写「未做破坏性利用」即可。

---

## 4. 定级

| 证据 | 建议 |
|---|---|
| 仅 DNS 回连，无 HTTP，无内网 | Low / 需说明可能是解析器；很多项目会降级。**只能记 open_proof_gap** |
| HTTP 回连，来源是目标服务器，可打公网 URL | Medium（盲 SSRF 已确认） |
| 能读内网/localhost 上 **in-scope 服务** 的响应 | High |
| 能读云元数据并拿到有效凭证 | Critical |
| 只有 open redirect、无服务端出网 | 不是 SSRF，别往这块套 |

---

## 5. 本平台工具对照

| 目的 | 工具 |
|---|---|
| 生成/查看 OOB | `oob_gen` `oob_poll` |
| 带 OOB 的模板扫描（需允许扫描） | `nuclei_oob_scan` |
| 发现 URL 参数 | `katana_crawl` `gf_filter` `ffuf_fuzz` |
| 登记 | 先 `src-triage`；candidate 才 `report_finding`（vulnclass=`ssrf`） |
| 复测 | `src-retest`（`max_redirs=0`；UA 必须是目标后端） |
| 报告 | `src-report-writing` |

不要用公共 `interactsh` 服务器；本环境已接 `oob.aiboli.top`。
