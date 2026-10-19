---
name: overseas-src-recon
description: 海外 SRC（HackerOne/Bugcrowd/Intigriti 等）授权 program 的资产侦察与初步漏扫标准流程。当需要对某个已授权 program 的 in-scope 资产做子域枚举、探活指纹、接口/历史URL发现、目录爆破、轻量漏扫时使用。内置 scope 合规检查与工具调用顺序。
---
# 海外 SRC 资产侦察流程

面向 **HackerOne / Bugcrowd / Intigriti** 等海外 SRC 平台，对**已授权 program 的 in-scope 资产**做系统化侦察。目标是：把攻击面铺全，为后续手工挖洞提供清单。

> **配套技能**：
> - `src-onboarding` —— 还没账号时只读公开 program；有账号才动手。公开范围 ≠ 授权。
> - `src-platform-scope` —— 开工前拉取三平台的 program 范围（API/工具）、核对自动化政策与合规清单。
> - `src-idor` / `src-xss` / `src-auth` / `src-ssrf` / `src-takeover` / `src-info-disclosure` / `src-business-logic` / `src-graphql` —— 授权后的手工漏洞测试。
> - `src-triage` —— **开洞前**判定是不是洞（挡 N/A、无影响、谎报、重复）。
> - `src-retest` —— 独立证据包；`not_a_vuln` 则不交。
> - `src-report-writing` —— 挖到洞后按三平台格式写报告、定 CVSS。

---

## 0. 铁律：先 scope，后动手

**先按 `src-platform-scope` 拉取并确认该 program 的 in-scope/out-of-scope 与政策**，再开始下面的侦察。

**任何请求发出前，先确认目标在 program 的 in-scope 列表内。**

- in-scope 才可碰；**out-of-scope（第三方、营销站、blog、状态页…）一律不碰**。
- 注意 program 的**自动化限制**：很多 program **禁止主动扫描 / fuzz / 高频请求**。若 program 禁止，只做被动信息收集（subfinder 被动源、gau/waybackurls、crt.sh），**不要**跑 ffuf/nuclei。
- 控制速率，避免给目标造成压力（可被判 DoS → 封号）。
- **不确定是否 in-scope 时，当作 out-of-scope 处理**。

> 本流程只在**授权范围内**使用。越界 = 封号 + 丧失奖金 + 法律风险。

---

## 1. 子域枚举（被动优先）

```
subfinder_enum(domain="example.com")
```
- 被动收集，相对安全，多数 program 允许。
- 想拿更多子域可在 subfinder 配第三方源 key（SecurityTrails/GitHub 等，可选）。
- 输出：子域清单。

**证书挖子域**（被动，很安全，很多子域没有 DNS 记录但证书里有）：
```
tlsx_cert(target="a.example.com,b.example.com")
```
- 返回 SAN 中的全部域名 → 追加进子域清单再探活。

## 2. 解析 + 探活 + 指纹

```
dnsx_resolve(targets="a.example.com,b.example.com,...")
httpx_probe(targets="https://a.example.com,http://b.example.com:8080")
```
- 先解析确认存活，再 httpx 探活。
- httpx 返回：状态码、标题、技术栈、服务器、内容长度。
- ⚠️ **已知坑 1**：部分 httpx 自带 DNS 解析器**不读 /etc/hosts**，对容器名/内网别名会解析失败。**优先用 IP**（Juice Shop 用 `http://172.18.0.3:3000`）。
- ⚠️ **已知坑 2（502）**：本环境有全局 HTTP 代理。内网 RFC1918 / juice-shop 必须绕过代理，否则代理回 502。`httpx_probe` **按目标分流**：内网清代理、公网走代理。**禁止**自己 `curl` 打内网却不带 `--noproxy '*'`。混打内网+公网时脚本会打印 `split: N private / M public`。

**CDN/WAF 识别**（避免把 CDN 节点当源站打）：
```
cdncheck_detect(target="a.example.com")
```
- 命中 `[waf][cloudflare]` 等说明目标在 CDN 后 → 扫它等于扫 CDN，误报多、也没意义。

## 3. 接口 / 路径发现

**a) 爬取（活站）**
```
katana_crawl(url="https://a.example.com")
```
- 爬链接、JS、表单、接口。加 `-jc` 已开 JS 解析。

**b) 历史 URL（被动）**
```
gau_urls(domain="example.com")
waybackurls_urls(domain="example.com")
```
- 找**旧接口、废弃参数、敏感路径**（老 API 常无鉴权）。
- ⚠️ waybackurls 依赖 archive.org，**大域名可能很慢（1-2 分钟）**；慢就用 gau_urls（多源，更快）。

**c) 目录/文件爆破（⚠️ 先确认 program 允许）**
```
ffuf_fuzz(url="https://a.example.com/FUZZ", wordlist="/usr/local/share/wordlists/common.txt")
```
- URL 里必须有 `FUZZ` 占位符。
- 字典全在 `/usr/local/share/wordlists/`，**按场景选，不要一上来用最大的**：

| 文件 | 行数 | 用途 |
|---|---|---|
| `common.txt` | 4751 | 快速摸底（优先用这个） |
| `raft-small-dirs.txt` | 20115 | 中等目录 |
| `raft-medium-dirs.txt` | 29999 | 更大目录（流量明显增加） |
| `dir-list-2.3-small.txt` | 87663 | DirBuster 小表，**更重**，仅 program 明确允许时用 |
| `api-endpoints.txt` | 295 | 常见 API 路径 |
| `api-common-mazen160.txt` | 174 | 精简 API |
| `api-seen-in-wild.txt` | 7615 | 实战见过的 API（噪声略大） |
| `graphql.txt` | 106 | GraphQL 入口 |
| `java-spring-boot.txt` | 202 | Spring Actuator 等 |
| `db-backups.txt` | 336 | 数据库备份文件名 |
| `burp-parameter-names.txt` | 6453 | 隐藏参数名（`?FUZZ=1`） |
| `url-params.txt` | 211 | 常见 URL 参数 |
| `raft-small-words.txt` | 43007 | 目录+后缀混用 |

- 示例：`ffuf_fuzz(url="https://a.example.com/api/FUZZ", wordlist="/usr/local/share/wordlists/api-endpoints.txt")`
- 示例：`ffuf_fuzz(url="https://a.example.com/search?FUZZ=1", wordlist="/usr/local/share/wordlists/burp-parameter-names.txt")`

**d) 降噪过滤（gf）**
```
gf_filter(file="/tmp/urls.txt", pattern="urls")     # 提取 URL
gf_filter(file="/tmp/urls.txt", pattern="takeovers") # 子域接管候选
gf_filter(file="/tmp/urls.txt", pattern="sec")       # 泄露的密钥/敏感信息
```
- 其他模式：`json-sec` `aws-keys` `s3-buckets` `cors` `debug-pages` `php-errors` `upload-fields` `servers` `ip` `base64` `http-auth`。
- **先过滤再测试**，能省掉 80% 的无效请求。

## 4. 轻量漏扫（⚠️ 先确认 program 允许）

```
nuclei_oob_scan(target="https://a.example.com")
```
- **带带外验证(OOB)**：接入自建 interactsh 服务器，OAST 类模板（盲 SSRF/RCE/XXE/Log4Shell）可正常验证。
- 若不需 OOB，用 `nuclei_scan`（关闭了 interactsh）。
- 社区模板 14000+，覆盖最新 CVE / 配置错误 / 暴露面。
- ⚠️ **全模板扫描很慢**（单站可能数分钟到十几分钟）。建议**按 tag/severity 缩小**，或对重点资产单独扫。
- 只扫 in-scope；命中后**手工验证**再报（nuclei 有误报）。
- **nuclei / dalfox / sqlmap 的 info、fingerprint、缺头、版本检测一律不是洞。** 先走 `src-triage`，candidate 才 `report_finding`，再 `src-retest`。禁止把扫描器输出直接当 finding。

**专项验证**（比通用模板更深）：
```
dalfox_xss(url="https://a.example.com/search?q=test")   # XSS
sqlmap_scan(url="https://a.example.com/item?id=1", level=1, risk=1)  # SQLi
```
- dalfox：自动识别反射参数 → 构造 payload → 验证真实触发，输出可复现 POC。
- sqlmap：**默认 level=1 risk=1 最保守**；调高会大幅增加请求量。
- ⚠️ 两者都是**主动扫描**，很多 program 明确禁止。**先确认 policy，优先手工验证。**

## 5. 带外验证 OOB（⚠️ 先确认 program 允许）

用于确认**不回显**的漏洞（盲 SSRF / 盲 RCE / 盲 SQLi / 盲 XXE / Log4Shell）：

```
1) oob_gen()                      → 拿到 OOB_DOMAIN 与 OOB_LOG
2) 把 OOB_DOMAIN 放进 payload（如让目标访问 http://<OOB_DOMAIN>/x）
3) 等 5-10 秒后 oob_poll(logfile=OOB_LOG)
   → 若出现 DNS/HTTP 交互，即证明目标发生了带外请求 = 漏洞确认（铁证）
```

- 每次测试用**新生成**的专属域名（唯一 id），避免串台。
- ⚠️ **合规**：OOB 请求会打到**你自己的服务器**。多数 program 允许**自建 OOB**，但**不少禁止公共 OOB 服务**（Intigriti 尤其多）——用前必看 policy。

## 6. 结果登记

- 把发现的资产（子域/IP/服务/接口）登记进资产库。
- 有价值的确认漏洞：先 `src-triage`，candidate 才登记为 finding（带证据/PoC），提交前 `src-retest`。
- 保持资产归属正确（不同 program 的资产不要混）。

---

## 工具速查

| 目的 | 工具 | 关键参数 |
|------|------|---------|
| 公开 program 摘要（非授权） | `public_src_programs` | platform, query/handle |
| 拉 scope(H1) | `h1_scope` | handle, username, token |
| 拉 scope(Bugcrowd) | `bugcrowd_scope` | handle, token |
| 拉 scope(Intigriti) | `intigriti_scope` | program_id, token |
| 证书透明度子域 | `crtsh_enum` | domain |
| URL 去重 / 抽参数 | `url_dedup` / `unfurl_parse` / `qsreplace_url` | file |
| 端口（仅明确 IP in-scope） | `naabu_ports` / `nmap_svc` | 默认少量 Web 端口 |
| JWT 解码 | `jwt_decode` | token |
| 带外验证(OOB) | `oob_gen` / `oob_poll` | 生成回连域名 / 查回连 |
| 漏扫(带OOB) | `nuclei_oob_scan` | target |
| 证书挖子域 | `tlsx_cert` | target |
| CDN/WAF 识别 | `cdncheck_detect` | target |
| XSS 专项 | `dalfox_xss` | url |
| SQLi 检测 | `sqlmap_scan` | url, level, risk |
| 模式过滤降噪 | `gf_filter` | file, pattern |
| 子域枚举 | `subfinder_enum` | domain |
| DNS 解析 | `dnsx_resolve` | targets(逗号分隔) |
| 探活+指纹 | `httpx_probe` | targets(逗号分隔) |
| 爬取 | `katana_crawl` | url |
| 历史URL | `gau_urls` / `waybackurls_urls` | domain |
| 目录爆破 | `ffuf_fuzz` | url(含FUZZ) + wordlist |
| 漏扫 | `nuclei_scan` | target |

## 推荐顺序

```
subfinder_enum → dnsx_resolve → httpx_probe → katana_crawl
                                        ↘ gau_urls / waybackurls_urls
→ (允许则) ffuf_fuzz → (允许则) nuclei_scan → 手工验证 → 登记
```

## 合规红线（海外 SRC 特别注意）

1. **只碰 in-scope**，不确定就不碰。
2. **遵守 program 自动化规则**，禁止扫描就只做被动收集。
3. **限速**，别把目标打挂。
4. 只做**最小必要验证**，别深入利用到破坏数据。
5. 报告前**手工确认**，减少误报。