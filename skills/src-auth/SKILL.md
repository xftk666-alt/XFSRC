---
name: src-auth
description: 海外 SRC 授权范围内的认证/会话漏洞测试（注册、登录、密码重置、JWT、OAuth/OIDC、会话固定、MFA 绕过）。当目标有登录态、token、SSO 或账号体系、需要按 H1/Bugcrowd/Intigriti 要求做最小验证时使用。禁止爆破密码、禁止打真实用户。
---
# 海外 SRC：认证 / 会话 / JWT / OAuth

已授权 program。目标：用**自己的测试账号**证明能接管账户、读他人会话或绕过登录——**最小必要验证，不爆破、不锁号**。

配套：`src-platform-scope`（是否允许多账号/重置密码）→ 本技能 → **`src-triage`（用户枚举 / 无 MFA / 前端改 role 不是洞）** → `src-retest` → `src-report-writing`。

---

## 0. 合规

- [ ] in-scope；policy 允许账号体系测试
- [ ] **只注册测试号**（A/B）；禁止对真实邮箱做重置
- [ ] 禁止密码喷洒、验证码爆破、撞库
- [ ] 锁定/DoS 类（把别人锁死）多数 **out-of-scope 或拒收**
- [ ] OAuth 回调必须是 **in-scope 客户端**，不要拿去打第三方 IdP

---

## 1. 先摸清认证面

浏览器 MCP 走一遍：注册 / 登录 / 记住我 / 登出 / 忘记密码 / 改邮箱 / 改密码 / MFA / 「用 Google 登录」。

`api-recon` 或 `katana_crawl` 找：

`/login` `/register` `/forgot` `/reset` `/token` `/oauth` `/authorize` `/refresh` `/mfa` `/verify`

JWT：响应或 localStorage 里拿到 token 后：

```
jwt_decode(token="<JWT>")
```

只解码，**不爆破密钥**。看 `alg` / `sub` / `role` / `exp` / `kid`。

---

## 2. 最小测试清单（每项最多几次请求）

| 主题 | 怎么测 | 算洞的证据 |
|---|---|---|
| 注册 | 角色字段 `role=admin`、邮箱已存在的差异响应 | 能自助拿管理员 / 枚举用户 |
| 登录 | 改响应 `{"ok":true}` 只影响前端 → 不是洞；直接调管理 API 才是 | 无凭证调用管理接口 200 |
| 会话固定 | 登录前记 cookie，登录后是否换 session | 登录后仍是预登录 cookie 且能当已登录 |
| 登出 | 登出后旧 token 仍能调 API | refresh/access 仍有效 |
| 重置密码 | Host 头 / 换 token 用户 / 短 token | 能把 B 的邮箱重置到 A 控制的地址 |
| 改邮箱 | 不验证旧邮箱、改完不失效会话 | 接管 |
| JWT `alg=none` | 去签名再提交 **一次** | 服务端接受 |
| JWT 改 `sub`/`role` | 只改 payload 重放 **一次**（HS256 无 secret 通常失败，失败就停） | 变成 B 或 admin |
| kid/jku | 指向你的 OOB 或 in-scope 文件 **一次** | 服务端去拉密钥（SSRF+认证绕过） |
| OAuth `redirect_uri` | 改到你控制的 in-scope 或 OOB **一次** | 授权码落到你这边 |
| MFA | 响应里 `mfa_ok:true`、备份码、跳过 endpoint | 无第二因素进入 |

**禁止**：hashcat 撞 JWT、对 `/login` ffuf 密码本、把 MFA 打爆。

---

## 3. 定级

| 影响 | 建议 |
|---|---|
| 无交互接管任意账户 | Critical |
| 能改他人密码/绑定邮箱 | High |
| 登录绕过进自己本不能进的角色 | High |
| 用户枚举 only | **默认不报**（`src-triage` drop；除非接到重置接管） |
| 无过期的 refresh 但需已有 token | Medium（看能否从 XSS 链上） |

---

## 4. 工具

| 目的 | 工具 |
|---|---|
| 解码 JWT | `jwt_decode` |
| 点登录流程 | `browser` MCP |
| 接口发现 | `api-recon` `katana_crawl` |
| 带外（jku/kid SSRF） | `oob_gen` `oob_poll` + `src-ssrf` |
| 登记 | 先 `src-triage`；candidate 才 `report_finding`（vulnclass=`auth-bypass` / `broken-auth`） |
