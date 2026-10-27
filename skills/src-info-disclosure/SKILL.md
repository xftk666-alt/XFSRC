---
name: src-info-disclosure
description: 海外 SRC 授权范围内的敏感信息泄露测试（.git/.env/备份/debug/目录列表/错误栈/JS 密钥）。当侦察发现异常路径、历史 URL、或前端 bundle 含密钥时使用。强调最小下载、不扩散数据、按实际影响定级。
---
# 海外 SRC：信息泄露（源码 / 备份 / 密钥 / Debug）

已授权 in-scope。目标：用**少量请求**证明可下载不该公开的数据；**不要**把整个 `.git` 拖走散播。

配套：`overseas-src-recon` → 本技能 → `src-report-writing`。

---

## 0. 合规

- [ ] 路径所在 host in-scope
- [ ] 禁止把泄露的客户 PII/密钥发到公共 gist
- [ ] 证明存在即可：下载**最小片段**（配置键名、一个 commit、一行 secret 前缀）
- [ ] 公开营销站上的 `robots.txt` 不是洞

---

## 1. 找点

字典（**仅 policy 允许目录爆破时**，先用小表、限速）：

```
ffuf_fuzz(url="https://in-scope/FUZZ", wordlist="/usr/local/share/wordlists/db-backups.txt")
ffuf_fuzz(url="https://in-scope/FUZZ", wordlist="/usr/local/share/wordlists/common.txt")
```

常见路径（可逐条 GET，不要全站递归）：

`/.git/HEAD` `/.git/config` `/.env` `/.env.bak` `/backup.sql` `/debug` `/actuator` `/actuator/env` `/server-status` `/phpinfo.php` `/swagger.json` `/graphql` `/.DS_Store` `/wp-config.php.bak`

历史 URL：`gau_urls` → `url_dedup` → `gf_filter(pattern="sec")` / `aws-keys` / `s3-buckets`。

前端：`katana_crawl` 的 JS → 本地搜 `AKIA` `api_key` `secret` `-----BEGIN`（用 Bash/grep，**不要**把整份 bundle Read 进上下文）。

Spring：`java-spring-boot.txt`。

---

## 2. 验证

| 发现 | 怎样才算可报 |
|---|---|
| `.git/HEAD` = `ref: refs/heads/...` | 再取 1 个 object 证明可读；不要 dump 全库 |
| `.env` 含 `AWS_SECRET` / DB 密码 | 打码后展示键；**不要**真去用这个密钥扫 AWS（除非 program 明确允许且密钥属于他们） |
| Actuator `/env` | 能看到属性 |
| 备份文件 | 文件头是 SQL/tar/zip 且含业务表名 |
| JS 里的第三方 API key | 证明 key **有效且属于该 program 资产**；Google Maps 浏览器 key 常被拒 |
| 目录列表 | 能列出非公开目录文件 |
| 详细错误栈 | 有内部路径/版本且能辅助进一步利用时才有价值，纯栈可能 Informational |

**误报**：示例密钥、故意公开的 changelog、CSP report-only、404 页指纹、**SPA fallback（任意路径 200 且 sha256 与首页相同）**、公开静态目录、Google Maps 浏览器 key。过不了 `src-triage` 不要 `report_finding`。

---

## 3. 定级

| 影响 | 建议 |
|---|---|
| 生产 DB/云根凭证，可验证有效 | Critical/High |
| 源码可读且含未公开漏洞或密钥 | High |
| 内部调试页无凭证 | Medium/Low |
| 版本号/public swagger | 常无奖金 |

---

## 4. 工具

`ffuf_fuzz` `gau_urls` `gf_filter` `katana_crawl` `httpx_probe` `nuclei_scan`（仅允许扫描时，tags 如 `exposure,config,git`）  
先 `src-triage`；candidate 才 `report_finding`（vulnclass=`info-disclosure`）→ `src-retest`
