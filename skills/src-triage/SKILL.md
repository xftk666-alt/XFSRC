---
name: src-triage
description: 海外 SRC 提交前的「是不是洞」判定。在 report_finding 之前把 HackerOne/Bugcrowd/Intigriti 常见 N/A、无影响、误报、谎报挡掉。当 worker 声称发现漏洞、或用户怕 AI 把非洞当洞时必须先走本技能。
---
# 海外 SRC：「是不是洞」判定（HackerOne / Bugcrowd / Intigriti）

给编排助手 / worker / retester。目标：把 **不是漏洞、无安全影响、证据是编的、重复洞** 挡在 `report_finding` 之前。

配套：发现用各 `src-*`；本技能是 **开洞前门禁**；独立复测用 `src-retest`；写报告用 `src-report-writing`。

> Juice Shop 彩排已经证明：同一 `/ftp` 会被报两次；评分越界（rating=-1）会被当成业务逻辑洞；SPA 统一回首页会被当成信息泄露。**三家真实 program 的 triage 比靶场更严。**

---

## 0. 流水线（不许跳）

```
假设有洞
  → 本技能 src-triage     判定 drop / candidate / needs-human
  → 只有 candidate 才允许 report_finding
  → src-retest            磁盘证据包 + attack/control
        retest_strict_gate（正文必须含受害者字段，禁止只看 200）
        reproduced | not_a_vuln | fixed | inconclusive
  → 签名 gate.json + 现场重算才允许写 reproduced（手改 ok=true 无效）
  → submit_advice 默认 needs-human；ready 必须用户亲口口令+challenge
  → src-report-writing
  → 用户在三家网页点提交（系统不能代点）
```

**铁律：**

1. **没过本技能 = 禁止 `report_finding`。** worker 口述「确认了」不算。
2. **过了本技能 ≠ 能交。** 还要过 `src-retest` 证据包。
3. **不确定 = drop 或 needs-human，绝不 candidate。**
4. **教学靶场 / CTF 永远 `submit_advice=never`**，即使技术上是真洞。
5. 未加入且 accepted 的真实 program：**禁止对真实资产发任何请求**（见 `src-onboarding`）。

**前置技能：**

- 发任何请求前 → `src-scope-guard`（scope_check fail closed）
- 判定候选到底是 confirmed / ruled_out / open_proof_gap → `src-closure`
- 任务收尾要声称「测完了」→ `src-coverage`

---

## 1. 六问全过才是 candidate

每一问必须能用**一句话 + 将要留下的证据**回答。任一题是「否 / 说不清」→ `drop` 或 `needs-human`。

| # | 问题 | 否 → |
|---|---|---|
| 1 | 资产在**你已加入且 accepted** 的 in-scope 内？（靶场练习除外） | drop（越界） |
| 2 | 是否跨过**安全边界**？即能读/改**别人的**数据、提权、在**他人浏览器**执行 JS、未授权拿到机密 | drop（无影响） |
| 3 | attack vs control **只改一个变量**后，响应里出现了**受害者/特权/机密字段**（不是只看 HTTP 200） | drop（未证明） |
| 4 | 不在下面「直接丢弃 / 默认丢弃」目录里？ | drop（N/A） |
| 5 | 不是本任务已有 finding 的同一根因？（同一路径+同一缺陷只留一条） | drop 或合并 |
| 6 | 影响能写具体、不夸大，且 program policy 没把这类列为 OOS？ | drop / needs-human |

写给自己看的一句话模板（过不了就不要开洞）：

```
用 <角色A> 的凭证，只改 <一个变量>，对 <URL> 做到了 <具体事>；
对照 <角色A自己的对象 / 无凭证 / 无 payload> 做不到；
受害者字段是 <邮箱/UserId/金额/dialog.message> 。
```

---

## 1.5 判重五问（第 5 问的展开，开洞前必做）

**Juice Shop 彩排里 `/ftp` 被报了两遍（finding 7 high + finding 10 medium），同一 PoC、同一字节数。** 这就是判重没做。

开洞前用 `search_finding_duplicates` + `list_task_findings`，然后逐条回答：

| # | 问题 | 全「是」→ |
|---|---|---|
| 1 | **同根因**？（同一处缺陷逻辑，不是「同一类漏洞」） | 候选重复 |
| 2 | **同组件/端点**？（同一个 handler、同一个中间件、同一处配置） | 候选重复 |
| 3 | **同利用方式**？（同一请求、同一参数、同一 payload 路径） | 候选重复 |
| 4 | **同一个补丁能同时修好两者**？ | 候选重复 |
| 5 | 两者**不能**用不同 sink / 不同失效控制点 / 不同影响来区分？ | 候选重复 |

**五问全「是」= 重复。** 处理方式：

- 已有 finding 且结论正确 → **不要再开新 finding**，用 `update_finding_report` 补充
- 已有 finding 但**定级错了** → 也**不要开新的**；走 `merge_finding_records` / `suggest_finding_merge`，或修订原记录
- 只是怀疑重复、证据不足 → `suggest_finding_merge` 交人工确认

### 反过来：一个根因 ≠ 一个候选

同一条路由上的多个问题，**按 sink / 失效控制点 / 影响**拆分：

- 一个危险 helper 有 6 个调用点，4 个独立可达 → **4 个候选**
- 同一路由上的命令执行 / SSRF / 路径写入 / 鉴权绕过 → **不同漏洞**
- 共享 URL ≠ 共享 bug

判据：**如果修好 A 不能同时修好 B，它们就是两个洞。**

### ⚠️ 短路径判重陷阱（已修复，但写报告时要自己留意）

`submit_brief.py` 曾经用 `len(prefix) >= 5` 过滤路径前缀，导致 `/ftp`、`/api`、`/v1`、`/sso`、`/jwt` 这类 4 字符以内的路径**完全不参与判重**。2026-10-19 已修为 `>= 2`。

但**工具修了不代表内容就对了**。写报告时仍要自己检查：

- 报告里的路径是 `/ftp` 还是 `/ftp/acquisitions.md`？后者判重更容易命中
- 同一接口的不同参数位置（query / body / header / path）算不算同一洞？看第 1.5 节五问
- 同一目录下的不同文件（`/ftp/acquisitions.md` 与 `/ftp/incident-support.kdbx`）→ **同一根因**（未认证目录挂载），不是两个洞

自查命令：

```bash
python3 /app/skills/src-retest/scripts/dup_check.py \
  --task-id 6 --kind info-disclosure --host 172.18.0.3 --path /ftp
```

返回非空（退出码 3）→ 先处理重复，再决定是否开洞。

---

## 2. 判定枚举

| 值 | 何时 | 下一步 |
|---|---|---|
| `drop` | 非洞、无影响、OOS、假证据、重复 | **不要** `report_finding`。笔记里写原因即可 |
| `candidate` | 六问全过，影响具体 | 才允许 `report_finding`，然后必须 `src-retest` |
| `needs-human` | 技术上像洞，但奖金边界/重复/真实用户数据/policy 灰区 | 不要交；把证据包路径交给用户 |

复测阶段另有 `not_a_vuln`（见 `src-retest`）：开洞之后才发现不是洞，也要显式记下来，避免再次交出去。

---

## 3. 直接丢弃（三家几乎一律 N/A / Informative / P5）

**缺安全头 / 最佳实践（不是漏洞）：**

- 缺 CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy / X-XSS-Protection
- Cookie 缺 `Secure` / `HttpOnly` / `SameSite`，但该 Cookie **不持有会话**，或没有配套 XSS/CSRF 利用
- TLS 配置「不够完美」（缺 CAA、中间套件、无证书透明度），**没有**可利用的降级/拦截 PoC
- 服务器/框架版本出现在 `Server` / `X-Powered-By` / 错误页
- `robots.txt` / `sitemap.xml` / 公开 changelog
- TRACE / OPTIONS / 无利用的 HTTP 方法
- 混合内容（HTTP 资源）、Tabnabbing、`window.opener` 无敏感操作
- 密码框 `autocomplete=on`
- 缺 DNSSEC / SPF / DKIM / DMARC（除非 program 明文收）
- 缺证书固定（Web 端）
- 点击劫持：页面**没有**敏感状态改变（改邮箱/改支付/删账号）。纯展示页 iframe = 丢弃
- CSRF：登出 CSRF、无登录态表单、纯 GET、无状态改变
- CORS `Access-Control-Allow-Origin: *` 且接口是**公开 GET、无凭证、无敏感数据**
- 开放重定向：只跳到外部 URL，**偷不到 token / 绑不上 OAuth / 不能钓鱼到已登录敏感操作**（多数 P5 或 OOS；能偷 OAuth code 才留下）

**枚举 / 策略类（无接管）：**

- 用户名 / 邮箱枚举（登录、注册、重置的差异响应）——除非能链式打到重置接管
- 密码策略弱、无 MFA、无验证码、会话过长
- 缺速率限制（非认证接口，或无法证明账户锁定/爆破可利用；**禁止真爆破**）
- 注册不验证邮箱
- 图形验证码可被 OCR / 回显 answer（无后续影响时）

**XSS / 前端假阳性：**

- Self-XSS（要受害者自己打开控制台粘贴）
- JSON / API 回显了 `<script>`，**浏览器未执行**（无 `dialog_executed=true`）
- 仅 `innerHTML` 有标签字符串，没有 dialog / 没有 JS 副作用
- 需要 `javascript:` 地址栏、或仅自己的资料预览
- 存储型打到自己，无法打到 **B 的会话**

**信息泄露假阳性：**

- SPA fallback：未知路径 200，body 长度 / ETag / sha256 **与首页相同**
- 公开静态目录列表（css/js/图片）
- 示例密钥、文档里的 `YOUR_API_KEY`、故意公开的 swagger（无未文档化管理接口、无密钥）
- Google Maps / reCAPTCHA / 浏览器限制过的第三方 key
- 详细错误栈只有路径/版本，**无密钥、无 PII、不能继续打**
- `.git` 返回 HTML 首页或 403 空页

**IDOR / 认证假阳性：**

- 200 但 JSON 是**自己的**数据、空对象、`{}`、通用错误页（复测闸门要求 IDOR 必须有 `control-self`：同一 token 读自己的对象，marker 不得出现在 self 包里）
- 对象本就是公开的（公开 profile、公开商品、公开帖子）
- 仅前端隐藏按钮，直接调 API 仍 403
- 改前端 JSON `role=admin` 页面显示变了，**管理 API 仍 401/403**
- GUID/UUID 不可枚举且无泄漏渠道（随机 id 猜不到 ≠ 已证明 IDOR）

**SSRF 假阳性：**

- 客户端 follow 了 302（浏览器/curl `-L`），OOB 打到的是**你自己的 UA**
- 只能打到公网无害 URL，无内网/云 metadata/文件读取
- 盲 SSRF 无 OOB、无时间差、无内容打回

**业务逻辑无安全影响：**

- 输入校验松（评分 0～5 写成 -1、显示名允许特殊字符）**且不导致钱/权/数据问题**
- 验证码可 bypass 但接口本身无敏感操作
- 「可以刷点赞/刷浏览」若 program 不收、或无经济影响
- 优惠券/价格问题若**只影响自己测试单、不能损害平台或其他用户**，按 program 赏金表；**不能证明资金/库存影响 = 不要报 High**

**范围 / 利用前提非法：**

- out-of-scope 资产、第三方 SaaS、营销站、状态页
- 需要 MITM、物理接触、已是管理员、社会工程、受害者先中木马
- DoS / 资源耗尽（三家多数 OOS；禁止去打）
- 理论漏洞、无 PoC
- 使用真实用户数据「证明」影响

---

## 4. 默认丢弃，除非拿出对照证据

这些**可以**是洞，但 AI 最爱误报。没有 attack/control 文件 = 仍按 drop。

| 声称 | 必须看到 |
|---|---|
| IDOR | A 的 token + B 的 id → **B 的邮箱/UserId/金额**；无 token 应为 401/403 |
| 垂直越权 | 普通用户调管理接口 200 **且数据像管理面**；不是只打开了 `/admin` 前端路由 |
| XSS | `browser_xss_evidence` 的 `dialog_executed=true` + 截图；存储型还要 A 写 B 看 |
| SSRF | `max_redirs=0`；OOB 日志 UA 是**目标后端**，或响应/头像变成内网资源正文 |
| 信息泄露 | body sha256 ≠ 首页；正文有密钥/目录项/PII |
| JWT alg=none | 伪造 token 调 whoami/管理 API 得到**伪造身份**；无 token 401；残缺 token 失败 |
| 账户接管 | 能登进 **B**，不是改了自己的资料 |
| 开放重定向 | 能偷 OAuth `code`/`token` 或把已登录用户带到攻击者页并完成敏感操作 |
| 子域接管 | NS/CNAME 悬空 **且** 你能完成服务商认领证明（见 `src-takeover`）；只报 CNAME 不够 |
| 业务逻辑（价格/券/数量） | 订单/钱包/角色在 **attack 响应**里与 control 不同，数字以本次 `response.body` 为准 |

---

## 5. 谎报（直接否决，当 drop）

Worker 文本 ≠ 证据。出现任一条，当**谎报**处理：

- 只有 Markdown / 聊天复述，没有 `http_evidence_record` 写下的 `cases/*/response.body`
- 数字从旧报告复制（用户数 24→29、金额抄 `-999999`）
- 复用 worker 落盘的 JWT / 订单号当「我复测了」
- XSS 用 curl 200 当执行
- 把扫描器模板名（nuclei `tech-detect`、目录 200）当漏洞
- 同一根因开两条 finding（Juice Shop `/ftp` finding 7 与 10）
- 靶场洞写成「可交 H1」

发现谎报：**不要**为了圆谎补写报告。记 `drop` / 复测记 `not_a_vuln`。

---

## 6. 三家 triage 口径（写报告前对齐）

| | HackerOne | Bugcrowd | Intigriti |
|---|---|---|---|
| 常见关闭 | N/A / Informative / Duplicate / Spam | Won't Fix / Not Applicable / P5 | N/A / Informative |
| 最佳实践 | 几乎都 Informative | VRT **P5** 一堆（缺头、版本、枚举） | 多数 N/A |
| 要什么 | 可复现 + **实际影响** | VRT 对号 + CVSS，选错类别会降级 | CVSS 3.1 向量 + 英文 PoC |
| 最恨 | 无 PoC、夸大、OOS、重复 | 扫出来的 P5 当 P2 交 | 公共 OOB、主动扫描、无影响 |

**定级不要按「类型名称」而要按「这次证据里的影响」：**

- 反射 XSS 能执行 ≠ Critical
- IDOR 读到公开昵称 ≠ High
- 目录列表只有静态资源 ≠ Medium
- 未授权读到他人订单 PII → 才按 C:H 考虑

**2026-10-19 起，`submit_brief` 的定级天花板已从「按漏洞类型」改为「按证据形态」**（`IMPACT_CEILING`）。实测变化：

| 声称 | 旧 ceiling | 新 ceiling |
|---|---|---|
| `.git` 泄露生产库密码 | low ❌ | critical ✅ |
| S3 泄露 200 万用户 PII | low ❌ | high ✅ |
| JS 里 AWS key 已验证 | low ❌ | critical ✅ |
| 管理员面板存储型 XSS | medium ❌ | high ✅ |
| 纯静态目录列表 | low | low（不变） |
| 缺 CSP | do-not-submit | do-not-submit（不变） |

规则：**证据里出现什么后果，才允许说到哪一档。** 没有对应后果描述时，退回按漏洞类型的保守兜底。

提交前查 Hacktivity / 该 program 已知问题，避免 duplicate。

---

## 7. Agent 操作清单（每次开洞前复制）

```
[ ] 前置：目标 host 已过 scope_check（in-scope）
[ ] 前置：候选已按 src-closure 收敛为 confirmed（不是 open_proof_gap）
[ ] 六问都是「是」，一句话模板填得完
[ ] 判重五问都是「否」（不是同一根因/组件/利用方式/补丁）
[ ] 不在「直接丢弃」目录
[ ] 「默认丢弃」类已有对照条件（将写入证据包）
[ ] search_finding_duplicates / 本任务 list_task_findings 无同一根因
[ ] 判定 = candidate  → 才 report_finding
[ ] 判定 = drop       → 停止，不写 finding
[ ] 判定 = needs-human → 把草稿和疑问交给用户，不提交
[ ] 已写入覆盖台账（coverage_record.py）
```

开洞之后仍须 `src-retest`：`retest_strict_gate` → `retest_verdict`。  
复测若证明不是洞：`verdict=not_a_vuln`，`submit_advice=never`。  
没有 `gate.json` ok=true，禁止任何人（含 Agent）宣称 reproduced。

---

## 8. 本平台工具

| 目的 | 工具 |
|---|---|
| 本任务已有洞（查重复） | `list_task_findings` `search_finding_duplicates` |
| 读原证据 | `get_finding_record` `get_finding_traffic` |
| 真正留下 HTTP 对照 | `http_evidence_record` `http_evidence_compare` |
| 字段级硬闸门 | `retest_strict_gate` `retest_verdict` `retest_signoff` `evidence_gate` |
| XSS 是否执行 | `browser_xss_evidence` |
| 合并同一根因 | `merge_finding_records` / `suggest_finding_merge` |
| 公开范围（≠授权） | `public_src_programs` |
| **范围校验** | `scope_check.py --task-id N --url U` |
| **覆盖台账** | `coverage_record.py` / `coverage_report.py` |
| **判重自查** | `dup_check.py --task-id T --kind K --host H --path P` |
| **靶场识别** | `lab_detect_cli.py`（CLI：`python3 lab_detect_cli.py --url/--host/--pack`，只读）；判定规则在 `lab_detect.py`，闸门内部直接 import |

**禁止**：为了让六问「看起来像是」而去打真实用户、爆破、DoS、越出 scope。
