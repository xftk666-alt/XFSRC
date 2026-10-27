---
name: src-oauth-saml
description: 海外 SRC 授权范围内的 OAuth 2.0 / OIDC / SAML 深度测试。OAuth 覆盖 redirect_uri 绕过、state CSRF、code 重放、PKCE 降级、scope 提升、账号预注册接管；SAML 覆盖签名包裹(XSW)、注释截断、XXE、断言重放、受众/接收方校验、未签名断言。用于企业 SSO、社交登录、单点登录场景。
---
# src-oauth-saml — OAuth / OIDC / SAML 深度测试

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program 的 SSO / 社交登录 / 企业身份联邦。本技能是 `src-auth` 的**深挖补充**：`src-auth` 管通用登录/会话，本技能只管 OAuth/OIDC/SAML 的协议层缺陷。

配套：`src-scope-guard` → `src-auth`（基础）→ 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope；**IdP 通常不在 scope**，只测 program 自己的 SP/客户端
- [ ] 只用自己注册的测试账号；禁止接管真实用户
- [ ] 禁止对 IdP 做密码喷洒/爆破
- [ ] 重定向接收端只用自建 OOB 或自己的 in-scope 测试域
- [ ] SAML 断言只用自己的账号生成/修改

---

## 1. OAuth / OIDC

### 1.1 先摸配置
```bash
curl -s "https://in-scope.example.com/.well-known/openid-configuration" | jq .
curl -s "https://in-scope.example.com/.well-known/oauth-authorization-server" | jq .
```
记录：`authorization_endpoint`、`token_endpoint`、`userinfo`、`jwks_uri`、支持的 `grant_types`、`response_types`、是否强制 PKCE。

### 1.2 redirect_uri 绕过（必测清单）
```
https://evil.example.com
https://in-scope.example.com.evil.example.com
https://in-scope.example.com@evil.example.com
https://in-scope.example.com/callback/../../evil
https://in-scope.example.com/callback?next=https://evil.example.com
https://in-scope.example.com/callback#@evil.example.com
https://IN-SCOPE.EXAMPLE.COM/callback
http://in-scope.example.com/callback          ← 协议降级
https://in-scope.example.com/callback%0d%0aLocation:https://evil.example.com
https://in-scope.example.com/callback/../other
https://evil.example.com?.in-scope.example.com
https://evil.example.com#.in-scope.example.com
```

**确认标准**：授权 `code`/`token` **真的落到你控制的地址**，并且你能用它换到 token / 调到受保护接口（如 `/me`）。**仅 302 到你的域名不算。**

### 1.3 state / CSRF
- 删除 `state` 仍能完成授权 → 可能 CSRF
- 复用旧 `state` 成功 → 同上
- 强制登录：用自己的账号构造授权链接，诱导逻辑只在自己浏览器验证

### 1.4 code / token 重放
- 同一 `code` 换两次，第二次仍返回 token → 缺陷
- `refresh_token` 是否轮换、旧的是否失效

### 1.5 PKCE 降级
- 授权请求带 `code_challenge`，换 token 时不带 `code_verifier` 仍成功 → 降级
- `code_challenge_method=plain` 是否被接受

### 1.6 scope 提升
- 请求 `scope=openid profile email admin`，看返回 token 是否真的获得高权限
- 用返回 token 调管理接口验证

### 1.7 账号接管（重点）
- **预注册接管**：用受害者邮箱先注册本地账号，再走 OAuth 登录，是否直接绑定
- **未验证邮箱绑定**：IdP 返回 `email_verified=false`，SP 是否仍信任
- **账号合并逻辑**：同邮箱不同 IdP 是否自动合并

**确认标准**：你能登录进一个**本不属于你**的测试账号（自己造的两个账号互相验证），而不是只看错误页。

---

## 2. SAML

### 2.1 抓断言
浏览器 DevTools / 代理抓 `SAMLResponse`（base64）。解出 XML：
```bash
echo "<base64>" | base64 -d | xmllint --format -
```

### 2.2 必测
| 测试 | 判据 |
|---|---|
| **签名包裹 XSW** | 复制合法签名断言，再插入一个改过 NameID 的未签名断言；若 SP 认了后者 → 接管 |
| **注释截断** | `admin@x.com<!-- -->@victim.com` 之类，看解析差异 |
| **未签名断言** | 删除 `<ds:Signature>` 后 SP 是否仍接受 |
| **签名位置** | 签名只覆盖部分节点（ID 引用可被移动） |
| **受众/接收方** | 改 `Audience` / `Recipient` / `Destination` 是否仍接受 |
| **时间窗** | `NotBefore`/`NotOnOrAfter` 是否校验；重放旧断言 |
| **XXE** | 断言解析器是否解析外部实体（用自建 OOB） |
| **RelayState** | 是否可注入开放重定向 |

**确认标准**：修改后的断言能让 SP 给你一个**有效会话**（登录进目标测试账号），且该修改本不应被接受。

### 2.3 工具
- 手工 base64/XML 编辑即可，不必上重型工具
- XXE 用 `oob_gen` 自建 OOB

---

## 3. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 302 到你的域名但 code 无效 | 未真正劫持 |
| 错误页/登录页 | 未认证 |
| state 缺失但会话绑定其他因素 | 需证明可 CSRF |
| 只改了断言但 SP 拒绝 | 校验正常 |
| 只在自己浏览器有效 | 未跨用户 |
| IdP 侧问题但 IdP 不在 scope | 不可报（除非影响 SP） |

---

## 4. 定级

| 证据 | 建议 |
|---|---|
| 账号接管（登录进他人账号） | Critical |
| code/token 被劫持并可调用 API | High~Critical |
| state CSRF 可强制绑定 | High |
| PKCE 降级但需其他条件 | Medium |
| scope 提升但无实际高权限数据 | Medium |
| 仅配置缺失、无利用 | Low / informational |

---

## 5. 工具对照

| 目的 | 工具 |
|---|---|
| 流程抓包 | browser 工具 / 代理 |
| OOB（XXE/回调） | `oob_gen` / `oob_poll` |
| 证据 | `http_evidence_record`（保存授权请求/回调/token 响应） |
| 台账 | `coverage_record`（risk=`oauth` / `saml`） |
| 复测 | `src-retest`（必须证明拿到可用会话/token） |

---

## 6. 报告要点

- 流程类型（授权码/隐式/混合；SAML SP-initiated/IdP-initiated）
- 具体缺陷与绕过串
- 拿到 code/token/会话的证据（脱敏）
- 影响：能登录谁的账号、能调哪些接口
- 修复：严格 redirect_uri 精确匹配、强制 state、code 一次性、强制 PKCE、校验签名覆盖范围与 Audience/Recipient/时间窗、禁用外部实体
