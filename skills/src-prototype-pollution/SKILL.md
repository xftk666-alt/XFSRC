---
name: src-prototype-pollution
description: 海外 SRC 授权范围内的原型链污染测试（客户端 DOM + 服务端 Node）。客户端看 ({}).polluted 是否落地并触发 gadget；服务端用 status/json spaces/charset 等可归因行为差分确认。覆盖 __proto__、constructor[prototype]、query/hash/JSON/postMessage 多来源。当目标是 JS 重应用、API 接受深合并 JSON 时使用。
---
# src-prototype-pollution — 原型链污染

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明污染**落在原型上**，并且**有 gadget 消费它**（DOM XSS / 鉴权标志 / RCE）。两阶段证据缺一不可。

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope
- [ ] 禁止用会导致服务崩溃的 payload（`__proto__` 覆盖 `toString`/`hasOwnProperty` 等核心方法要谨慎）
- [ ] 禁止持久化污染生产：验证后重新加载/重启会话，必要时通知厂商
- [ ] RCE 验证只用**无害标记**（如 `id`、`echo marker`），不做持久化、不写文件、不反弹 shell
- [ ] 单接口 ≤ 10 次

---

## 1. 客户端（DOM）

### 来源
```
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor[prototype][polluted]=true
?constructor.prototype.polluted=true
#__proto__[polluted]=true
JSON body: {"__proto__":{"polluted":"true"}}
postMessage: {"__proto__":{"polluted":"true"}}
```

### 确认
```javascript
// 浏览器控制台
({}).polluted            // 返回 "true" → 污染落地
Object.prototype.polluted
```

**必须再找 gadget**：污染属性是否被某个 sink 读取。
- `innerHTML` / `$.html()` / `document.write`
- `transport_url` / `src` / `href`
- 模板引擎配置（`escape`、`allowedTags`）
- 前端路由/状态合并

只有污染没有 sink → `open_proof_gap` 或 Low，不算 XSS。

---

## 2. 服务端（Node/Express 等）

### 探测
```bash
curl -s -X POST "https://in-scope.example.com/api/merge" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"status":510}}' -o /dev/null -w "%{http_code}\n"

curl -s -X POST "https://in-scope.example.com/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"json spaces":10}}'
```

### 可归因行为差分（至少一个）
| 差分 | 说明 |
|---|---|
| HTTP 状态变成 510 | 污染了 `status` |
| JSON 输出缩进/空格变化 | Express `json spaces` |
| `Content-Type` charset 变化 | 污染了相关属性 |
| 鉴权行为变化（`isAdmin`） | 需要能观测到权限变化 |
| 模板输出变化 | 需要无害标记 |

**普通 200 不算证据。**

---

## 3. 必测来源/语法（漏测高发）

- `__proto__`、`constructor.prototype`、`constructor[prototype]`
- query / hash / JSON body / form / `postMessage` / `localStorage` 反序列化
- 深合并接口：`merge`、`extend`、`defaultsDeep`、`clone`、`assign`
- 嵌套对象与数组下标（`a[0][__proto__][x]`）
- 不同 Content-Type（json / form / urlencoded）

---

## 4. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 上一次测试残留导致 `({}).polluted` 有值 | 刷新/新会话重测 |
| 只污染了实例，不是原型 | `obj.polluted` 有值但 `({}).polluted` 没有 |
| 服务端 JSON 库丢弃 `__proto__` | 无落地 |
| 行为变化是随机/缓存导致 | 需要可重复 ≥2 次 |
| 只有污染，无 gadget | 不能证明影响 |

---

## 5. 定级

| 证据 | 建议 |
|---|---|
| 客户端污染 + DOM XSS 实弹 | High |
| 服务端污染 + 鉴权绕过 | High~Critical |
| 服务端污染 + RCE（无害标记证明） | Critical |
| 仅污染落地，无 gadget | Low / informational |
| 仅理论可能 | 不报 |

---

## 6. 工具对照

| 目的 | 工具 |
|---|---|
| 客户端验证 | browser 工具 / `browser_evaluate` |
| 服务端差分 | curl + `http_evidence_record` |
| 台账 | `coverage_record`（risk=`prototype_pollution`） |
| 复测 | `src-retest`（两阶段证据都要有） |

---

## 7. 报告要点

- 污染来源（哪个参数/接口）
- 落地证据（`({}).polluted` 或状态码/JSON 差分）
- gadget 与 sink（哪个代码路径消费了它）
- 影响（XSS / 鉴权 / RCE）
- 修复：`Object.create(null)`、冻结原型、白名单键、禁用 `__proto__`/`constructor`/`prototype`
