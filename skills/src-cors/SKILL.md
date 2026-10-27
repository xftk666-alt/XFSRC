---
name: src-cors
description: 海外 SRC 授权范围内的 CORS 配置错误测试。判定标准是 ACAO 反射攻击者 Origin 且 ACAC=true，并用浏览器 fetch(credentials:'include') 实际读到响应体。覆盖 null Origin、子域/前后缀匹配绕过、协议降级、通配符+凭证。当 API 有跨域访问、SPA 前后端分离时使用。
---
# src-cors — CORS 配置错误

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明攻击者站点能**在受害者浏览器里带凭证读取**目标 API 的响应体。**只有响应头不算，必须浏览器实测读到正文。**

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope；只测 in-scope 的 API 域名
- [ ] 禁止用真实用户做验证；用自己两个测试账号
- [ ] PoC 页面放本地或自己的 in-scope 环境，不要挂公网钓鱼页
- [ ] 单接口探测 ≤ 20 次

---

## 1. 基础探测

```bash
curl -s -I -H "Origin: https://evil.example.com" \
  "https://api.in-scope.example.com/api/user/profile" \
  | grep -iE "access-control-allow-(origin|credentials|methods|headers)"
```

**高危组合**：
```
Access-Control-Allow-Origin: https://evil.example.com   ← 反射了你的 Origin
Access-Control-Allow-Credentials: true                  ← 允许带 Cookie
```

两者同时出现 = candidate；再用浏览器 PoC 确认能读到正文。

---

## 2. 必测 Origin 变体（不试完不许说 clean）

| 变体 | 目的 |
|---|---|
| `https://evil.example.com` | 任意源反射 |
| `null` | sandboxed iframe / data: URI |
| `https://evil.in-scope.example.com` | 任意子域（子域接管可升级） |
| `https://in-scope.example.com.evil.com` | 后缀匹配缺陷 |
| `https://evil-in-scope.example.com` | 前缀匹配缺陷 |
| `http://in-scope.example.com` | 协议降级 |
| `https://in-scope.example.com:443` / 加尾点 / 反引号 | 解析差异 |
| `*` 场景 | 通配符 + credentials 是否同时出现（浏览器会拒绝，但仍记录） |

---

## 3. 浏览器确认（必做）

```javascript
// 在攻击者源（本地 http://127.0.0.1:8000 或自己的测试域）打开
fetch('https://api.in-scope.example.com/api/user/profile', {
  credentials: 'include'
})
  .then(r => r.text())
  .then(t => console.log('LEAKED:', t))
  .catch(e => console.log('BLOCKED:', e));
```

- 先在目标站点登录测试账号 A
- 再从 PoC 页发起请求
- 能打印出 A 的账户数据 → **confirmed**
- 被浏览器拦截（CORS error）→ 头配置未真正可利用

**注意**：`SameSite=Lax/Strict` 的 Cookie 可能让 `credentials:'include'` 也带不上。要记录 Cookie 的 SameSite 属性；带不上则降级。

---

## 4. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| `ACAO: *` 且无 `ACAC: true` | 不能带凭证；仅公开数据 |
| 反射 Origin 但无 `ACAC: true` | 读不到需登录数据 |
| 只在公开端点反射 | 无敏感数据 |
| 预检通过但实际请求被拒 | 未形成读取 |
| 只有 `ACAO` 头，浏览器 fetch 失败 | 不可利用 |
| `Vary: Origin` 缺失但无缓存层 | 单独不构成洞（可提加固建议） |
| Cookie 是 `SameSite=Strict` | 跨站带不上 |

---

## 5. 定级

| 证据 | 建议 |
|---|---|
| 反射任意 Origin + 凭证 + 读到 PII | High |
| 反射任意 Origin + 凭证 + 只读到非敏感 | Medium |
| 仅子域反射 + 该子域可被接管 | High（与 takeover 组合） |
| `ACAO: *` 无凭证 | Low / informational |
| 仅 `Vary` 缺失 | Low |

---

## 6. 工具对照

| 目的 | 工具 |
|---|---|
| 头探测 | curl |
| 浏览器实测 | browser 工具 / `browser_evaluate` |
| 证据 | `http_evidence_record`（保存请求头与响应头）+ 浏览器截图/控制台输出 |
| 台账 | `coverage_record`（risk=`cors`） |
| 复测 | `src-retest`（必须浏览器读到正文） |

---

## 7. 报告要点

- 目标端点与 Origin 变体
- 完整响应头（ACAO / ACAC / Vary）
- 浏览器 PoC 代码与 `LEAKED:` 输出
- Cookie 属性（SameSite/HttpOnly/Secure）
- 影响：能读哪些数据、需要受害者做什么
- 修复：严格 Origin 白名单（精确匹配）、不要反射、按需 `ACAC`、正确设置 `Vary: Origin`
