---
name: src-xss
description: 海外 SRC 授权范围内的 XSS（反射/存储/DOM/盲 XSS）手工测试与验证流程。当页面或 API 有回显参数、富文本、消息、文件名、或需要核对 H1/Bugcrowd/Intigriti 对 XSS 的报告要求时使用。默认手工+浏览器验证；dalfox 仅在 program 明确允许主动扫描时用。
---
# 海外 SRC：XSS（反射 / 存储 / DOM / 盲）

已授权 program 的 in-scope 页面/接口。目标：用**最少请求**证明脚本能在**他人浏览器**里执行，并写出可复现 PoC。

配套：`src-platform-scope` → 本技能 → `src-report-writing`。

---

## 0. 开工前

- [ ] 目标 in-scope；不确定就停
- [ ] policy 是否允许 XSS 测试、是否把 self-XSS / 无会话 XSS 列为无影响
- [ ] **不要**对生产用户投递存储 XSS；用**自己的测试账号**互打
- [ ] 多数 program **禁止 dalfox/全站扫描** → 默认手工。仅 policy 允许时：`dalfox_xss(url="https://in-scope/search?q=test")`

---

## 1. 先找注入点（不要一上来扫）

来源：`katana_crawl` / `gau_urls` / `waybackurls_urls` → `url_dedup` → `gf_filter(pattern="xss")` 若有；否则看参数名 `q` `search` `name` `title` `message` `comment` `next` `redirect` `callback` `url`。

分类：

| 类型 | 特征 | 验证 |
|---|---|---|
| 反射 | 参数出现在 HTML/属性/JS 字符串 | 浏览器里 `alert` / `document.domain` |
| 存储 | 资料、评论、文件名、显示名 | 账号 A 存、账号 B 打开 |
| DOM | 前端 `location`/`innerHTML`/`postMessage` | 浏览器 MCP 看源；改 hash/query 不发服务端也能触发 |
| 盲 | 管理后台才渲染 | **自建 OOB**：`oob_gen` 后 payload 指向 `https://<OOB_DOMAIN>/xss`，`oob_poll` 看是否有管理员 UA（需 policy 允许 OOB） |

隐藏参数（仅允许 fuzz 时、单接口、限速）：

```
ffuf_fuzz(url="https://in-scope/search?FUZZ=xss", wordlist="/usr/local/share/wordlists/burp-parameter-names.txt")
```

---

## 2. 最小验证（禁止炮仗 payload）

顺序只改**一个**变量：

1. 提交无害标记：`srcxssprobe`（确认反射位置：HTML 正文 / 属性 / JS / HTTP 头）
2. 按位置选 **1 个** payload（不要字典爆破）：
   - HTML 正文：`"><svg/onload=alert(document.domain)>`
   - 属性：`\" onmouseover=alert(document.domain) x=`
   - JS 字符串：`</script><svg/onload=alert(document.domain)>` 或 `\u003cimg src=x onerror=alert(document.domain)>`
   - 仅 innerHTML 的 DOM：`<img src=x onerror=alert(document.domain)>`
3. 用 **browser MCP** 打开带 payload 的 URL，确认弹窗或 `browser_evaluate` 读到执行副作用
4. 存储型：A 写入、B 登录后打开，截图 + 请求/响应

**CSP**：有 CSP 不等于没洞。看是否 `unsafe-inline`、是否可绕过 nonce、是否只挡了 `alert`（改用 `fetch` 打 OOB 证明执行即可，不要偷真实用户 cookie）。

**Self-XSS**（必须控制台粘贴 / 只打到自己）很多项目拒收。不要报。

---

## 3. 定级（给报告用，勿虚高）

| 实际影响 | 建议 |
|---|---|
| 存储型，普通用户能打到其他用户会话（cookie/token/CSRF 动作） | High |
| 反射型需诱使用户点击带参链接，能执行任意 JS | Medium（有 HttpOnly+CSP 可能再降） |
| DOM XSS 同等 | 同反射/存储看触发条件 |
| 仅自己的资料预览、需自己粘贴 | 常拒收 |
| 只在 JSON 里、浏览器不执行 | 不是 XSS |

H1 weakness 常用 `XSS` / `Stored XSS`。Bugcrowd VRT：`Cross-Site Scripting`。

---

## 4. 证据

- 完整 URL 或 POST 体
- **提交前必须** `browser_xss_evidence`：`dialog_executed=true` + `screenshot.png` 进证据包（技能 `src-retest`）。仅 MCP 截图或 curl 回显不够。
- 存储型：A 写 / B 看 两条会话
- 说明未盗用真实用户数据

然后 `src-triage`（无 dialog / self-XSS / 仅 JSON 回显 = drop）→ `src-retest` → `src-report-writing`。

---

## 5. 工具对照

| 目的 | 工具 |
|---|---|
| 发现参数 | `katana_crawl` `gau_urls` `url_dedup` `unfurl_parse` |
| 浏览器验证 | `browser` MCP（探索） |
| XSS 独立证据 | `browser_xss_evidence`（dialog+截图落盘，复测必用） |
| 盲 XSS OOB | `oob_gen` `oob_poll` |
| 允许扫描时 | `dalfox_xss` |
| 登记 | 先 `src-triage`；candidate 才 `report_finding`（vulnclass=`xss`）→ `src-retest` |
