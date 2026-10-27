---
name: src-host-header-injection
description: 海外 SRC 授权范围内的 Host 头注入与 CRLF 测试。覆盖 Host、X-Forwarded-Host/Proto、X-Original-URL、X-Rewrite-URL、绝对 URI。用于验证密码重置链接劫持、缓存投毒、访问控制绕过、SSRF 路由。强调只用自己账号和自建 OOB，不碰真实用户邮件。
---
# src-host-header-injection — Host 头注入 / CRLF

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明应用**信任了客户端可控的 Host/转发头**，并造成实际影响（重置链接劫持、缓存投毒、访问控制绕过、SSRF）。

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope
- [ ] 密码重置类验证**只用自己的测试账号**，绝不触发真实用户邮件
- [ ] OOB 只用自建（`oob_gen`），不用公共 interactsh
- [ ] 不做大规模 Host 爆破；每个头 1~2 个变体
- [ ] CRLF 注入只验证响应头是否被拆分，不注入恶意跳转给真实用户

---

## 1. 必测头

| 头 | 常见影响 |
|---|---|
| `Host` | 重置链接、绝对 URL 生成、缓存键 |
| `X-Forwarded-Host` | 同上（反代常透传） |
| `X-Forwarded-Proto` / `X-Forwarded-Scheme` | 链接 scheme、重定向循环 |
| `X-Original-URL` / `X-Rewrite-URL` | 访问控制绕过（前端按路径拦，后端按头路由） |
| `X-Host` / `X-Forwarded-Server` | 同上 |
| 绝对 URI（`GET https://evil/ HTTP/1.1`） | 路由/缓存混淆 |

---

## 2. 探测

```bash
# 基础反射
curl -s -H "Host: canary.example.com" "https://in-scope.example.com/" | grep -i canary
curl -s -H "X-Forwarded-Host: canary.example.com" "https://in-scope.example.com/" | grep -i canary
curl -s -H "X-Forwarded-Proto: http" "https://in-scope.example.com/" -I | grep -i location

# 访问控制绕过
curl -s -H "X-Original-URL: /admin" "https://in-scope.example.com/" -o /dev/null -w "%{http_code}\n"
curl -s -H "X-Rewrite-URL: /admin" "https://in-scope.example.com/" -o /dev/null -w "%{http_code}\n"

# CRLF
curl -s -H $'X-Forwarded-Host: canary.example.com\r\nX-Injected: yes' \
  "https://in-scope.example.com/" -I | grep -i "x-injected"
```

---

## 3. 影响验证（必须落到具体后果）

### 3.1 密码重置链接劫持
1. 用**自己的测试账号 A** 发起忘记密码
2. 请求带 `X-Forwarded-Host: <你的OOB或测试域>`
3. 收到的重置邮件里链接域名是否变成你的
4. 点开确认 token 落到你控制的地址 → **confirmed**

> 只用自己邮箱；不要把真实用户邮箱放进流程。

### 3.2 缓存投毒
Host 头若未键控且被反射 → 与 `src-cache-poisoning` 联用，必须证明第二客户端收到污染内容。

### 3.3 访问控制绕过
`X-Original-URL: /admin` 返回管理页内容（而直接访问 `/admin` 被 403）→ **confirmed**（BFLA 类）。

### 3.4 SSRF / 路由
Host 被用于后端请求拼接 → 用 `oob_gen` 证明目标服务器发起请求（判据见 `src-ssrf`）。

---

## 4. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 头被忽略，页面不变 | 未信任该头 |
| 只反射在页面里，无后续动作 | 无影响（除非进缓存/XSS） |
| 重置链接来自配置常量 | 未使用 Host |
| 403 变成 200 但正文是错误页 | 软 404 |
| CRLF 被 WAF 规范化 | 未拆分 |
| 只有自己浏览器看到变化 | 未进共享缓存 |

---

## 5. 定级

| 证据 | 建议 |
|---|---|
| 重置链接劫持，可接管他人账号 | Critical |
| 访问控制绕过进入管理面 | High~Critical |
| 缓存投毒影响他人 | High |
| SSRF 证明后端出网 | Medium~High（按可达范围） |
| 仅头反射、无影响 | Low / informational |

---

## 6. 工具对照

| 目的 | 工具 |
|---|---|
| 头探测 | curl |
| OOB | `oob_gen` / `oob_poll` |
| 证据 | `http_evidence_record` |
| 台账 | `coverage_record`（risk=`host_header_injection` / `header_injection`） |
| 复测 | `src-retest` |

---

## 7. 报告要点

- 哪个头被信任、在哪个功能点
- 具体后果（邮件链接原文脱敏、绕过前后的状态码、缓存命中证据）
- 影响范围
- 修复：固定 `server_name`/`Host` 白名单、不信任转发头、重置链接用配置域名、拒绝 CRLF
