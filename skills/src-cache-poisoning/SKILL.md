---
name: src-cache-poisoning
description: 海外 SRC 授权范围内的 Web 缓存投毒与缓存欺骗测试。覆盖未键控头（X-Forwarded-Host 等）、缓存键构造、Vary、缓存欺骗路径。强调必须用 cache buster 隔离、干净复访确认、第二客户端验证，且不得影响真实用户。当目标在 CDN/反代之后、响应含 X-Cache/CF-Cache-Status/Age 时使用。
---
# src-cache-poisoning — Web 缓存投毒 / 缓存欺骗

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明**未键控输入被反射进被缓存的响应**，并**送达第二个客户端**。反射 ≠ 投毒；`MISS/DYNAMIC/BYPASS` ≠ 命中。

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] program 允许缓存类测试（未提 → 先问）
- [ ] **发现阶段必须带 cache buster**（唯一 query），避免污染共享缓存
- [ ] 验证共享影响时，只用**自己的第二个客户端/第二个账号**，不拿真实用户验证
- [ ] 命中后立即：记录 → 尽量 purge → 等待 TTL；不要留下持续投毒
- [ ] 禁止投毒登录页/支付页等高风险页面；优先选低流量路径
- [ ] 单路径探测 ≤ 15 个请求

---

## 1. 识别缓存层

```bash
curl -s -I "https://in-scope.example.com/" | grep -iE \
  "(cache-control|x-cache|cf-cache|age|vary|x-varnish|x-served-by|via|cdn)"
```

| 头 | 含义 |
|---|---|
| `X-Cache: HIT/MISS` | 通用缓存 |
| `CF-Cache-Status: HIT/MISS/DYNAMIC/BYPASS` | Cloudflare；**DYNAMIC/BYPASS = 未缓存，无投毒面** |
| `Age: N` | 已缓存 N 秒；复访时增长 = 命中 |
| `Vary` | 列出的头属于缓存键 |
| `Cache-Control: max-age/s-maxage` | 缓存窗口 |

缓存键通常是 `Host + Path + Query`。**未键控头**才是投毒入口。

---

## 2. 未键控头清单（逐个试，每次带 cache buster）

```
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Proto
X-Forwarded-Server
X-Original-URL
X-Rewrite-URL
X-Host
X-Forwarded-For
True-Client-IP
Origin
Referer
```

```bash
CB="cb=$(date +%s%N)"
curl -s -H "X-Forwarded-Host: canary.example.com" \
  "https://in-scope.example.com/path?$CB" | grep -i "canary.example.com"
```

**两个条件同时满足才有戏**：① 该头不在缓存键里（改它不改变缓存条目）② 它的值被反射进响应。

---

## 3. 确认判据（缺一不可）

1. **未键控 + 反射**（上面两条）
2. **干净复访**：去掉恶意头，用**同一个 URL**（不带 buster）再请求，仍返回你的 payload
3. **缓存命中证据**：`X-Cache: HIT` / `CF-Cache-Status: HIT` / `Age` 增长
4. **第二客户端**：换一个会话/账号/出口 IP，请求同一 URL，收到你的 payload
5. **有服务窗口**：`max-age`/`s-maxage` > 0，且 `Vary` 不包含你改的头

缺任一条 → `open_proof_gap`，不许报。

---

## 4. 缓存欺骗（cache deception）

思路：让缓存把一个**需要登录的动态页面**当成静态资源缓存下来，随后被未登录者读到。

```bash
# 用自己的账号 A 请求
curl -s -b "session=A" "https://in-scope.example.com/account/profile/x.css"
# 再用无 Cookie 请求同一 URL
curl -s "https://in-scope.example.com/account/profile/x.css"
```

- 若第二次返回 A 的账户内容 → candidate
- 必须确认：① 该路径确实命中缓存 ② 内容是**账户专属字段** ③ 不是你自己的浏览器缓存
- 常见后缀：`.css` `.js` `.jpg` `.png` `.ico` `.woff` `.svg`；分隔符：`;` `%00` `%2f` `..%2f`
- **禁止**用真实用户数据；只用自己的 A/B 账号

---

## 5. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 只有反射，复访消失 | 未进缓存 |
| `MISS/DYNAMIC/BYPASS` | 该响应不缓存 |
| `Age` 不增长 | 没命中 |
| `Vary: Origin` 等包含你改的头 | 已键控 |
| 第二客户端没收到 | 只影响自己 |
| 命中但内容是公开页 | 无安全影响 |
| 浏览器本地缓存 | 不是服务端缓存 |

---

## 6. 定级

| 证据 | 建议 |
|---|---|
| 未键控头可注入，但仅影响自己 | Low / 不报 |
| 可让第二用户收到攻击者内容（XSS/开放重定向） | High |
| 可缓存他人账户数据（缓存欺骗） | High~Critical |
| 可投毒全站静态资源 | Critical |
| 仅 `Vary` 缺失，无实际投毒 | Low / informational |

---

## 7. 工具对照

| 目的 | 工具 |
|---|---|
| 头反射探测 | curl（带 buster） |
| 证据 | `http_evidence_record`（保存 headers + body），第二客户端对照 |
| 台账 | `coverage_record`（risk=`cache_poisoning` / `cache_deception`） |
| 复测 | `src-retest`（必须含第二客户端证据） |

---

## 8. 报告要点

- 缓存层与缓存键判断依据
- 未键控头的具体名字与反射位置
- 干净复访的响应（含 `X-Cache`/`Age`）
- 第二客户端收到的内容
- 缓存 TTL 与服务窗口
- 影响范围（哪些路径/多少用户）
- 修复：把相关头加入缓存键、不要反射未键控头、`Vary` 正确设置、静态/动态路径隔离
