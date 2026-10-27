---
name: src-report-writing
description: 海外 SRC（HackerOne / Bugcrowd / Intigriti）漏洞报告的撰写规范与模板。当要把一个已确认漏洞写成可提交的报告、给漏洞定级(CVSS)、或按平台格式组织复现步骤/影响时使用。含三平台报告结构、常见拒收原因、可复现 PoC 要求与证据清单。开洞前走 src-triage；提交前必须先走 src-retest 独立证据包门禁。
---
# 海外 SRC 漏洞报告撰写（HackerOne / Bugcrowd / Intigriti）

目标：把一个**已确认**的漏洞，写成 triage 一眼能懂、能复现、定级合理的报告。

**不要写「不是洞」的报告。** 先 `src-triage`，再 **独立复测子任务**（`src-retest-dispatch`，不是 Auto 聊天、不是开洞 worker）跑通 `src-retest`：签名 `gate.json` 现场 ok、`verdict.json` 为 reproduced。靶场 / `not_a_vuln` / 无证据包 = 不写给三家。猎人自己粘贴提交，不要求 Auto 代签。

---

## 0. 报告三要素（三家通用）

1. **Summary**：一句话说清是什么洞、在哪、影响多大。
2. **Steps to Reproduce**：**最小、可复制**的步骤。带上完整请求/响应或命令。
3. **Impact**：攻击者能**实际**做到什么（读谁的数据、越什么权、执行什么）。**不要夸大**——夸大 = 降级或拒收。

> 原则：triage 是陌生人，**假设他什么都不知道**。步骤要能让他**原样照做**就复现。

---

## 1. 平台差异

| 项 | HackerOne | Bugcrowd | Intigriti |
|---|---|---|---|
| 结构 | Summary / Steps / Impact / (CVSS) | Summary / Steps / Impact / CVSS | Summary / Steps / Impact |
| 严重度 | severity_rating（none/low/medium/high/critical）+ weakness_id | VRT 分类 + CVSS | CVSS 3.1 |
| 附件 | 支持截图/文件 | 支持 | 支持 |
| 提交方式 | Web 表单 或 API `POST /v1/hackers/reports` | Web 表单 | Web 表单 |

### HackerOne 报告字段（API 提交时）
```
team_handle, title, vulnerability_information(含复现步骤),
impact, severity_rating, weakness_id, structured_scope_id
```
- `severity_rating` 现在**多数 program 必填**；缺失返回 422。
- 用 `structured_scope_id` 关联到具体 in-scope 资产，减少扯皮。

### Bugcrowd
- 按 **VRT（Vulnerability Rating Taxonomy）** 选分类；严重度用 **CVSS**。
- 选错 VRT 类别常导致降级，务必对号入座。

### Intigriti
- 用 **CVSS 3.1** 打分；报告要给出向量字符串。
- 部分 program 要求**英文**并附 PoC 视频/请求原文。

---

## 2. 报告模板

```markdown
# Title: <漏洞类型> in <端点/功能> leads to <影响>

## Summary
<2-3 句：什么洞、在哪、影响。>

## Affected Asset
- Program: <handle>
- Asset / URL: <https://target/path>
- In-scope 依据: <structured_scope / target>

## Steps to Reproduce
1. <登录为普通用户 A / 准备...>
2. <发送如下请求>
   ```http
   GET /api/v1/users/123 HTTP/1.1
   Host: target.com
   Authorization: Bearer <A的token>
   ```
3. <观察响应返回了 B 的数据>
4. <PoC / 截图 / 请求响应原文>

## Impact
- <具体能做什么：越权读取他人 PII / 接管账户 / 任意文件读取 ...>
- <影响范围：多少用户 / 哪些数据>

## Severity (CVSS 3.1)
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- Score: 6.5 (Medium)
- 理由: <为什么是这个分>

## Remediation
- <修复建议：服务端做对象级鉴权 / 参数化查询 / 输出编码 ...>

## Counterevidence（我试过什么，为什么它不是这个洞）
- 对照实验: <同一请求去掉攻击参数 / 换成自己的 ID / 换成不存在的 ID，分别返回什么>
- 已排除的替代解释: <比如「返回了数据」不是因为越权，而是因为该资源本来就公开>
- 结论: <哪一条对照直接排除了替代解释>

## Confidence（置信度）
- 等级: high | medium | low
- 依据: <gate.json ok + verdict reproduced + 对照实验可重复>
- 不确定的地方: <环境差异 / 需要特定角色 / 时间窗口 …；没有就写 none>

## Severity Change Conditions（什么情况下这个等级会变）
- 升级条件: <拿到管理员会话 / 证明可批量枚举 / 证明数据属于他人>
- 降级条件: <数据实际是公开的 / 需要受害者主动配合 / 仅影响自己>

## Evidence Binding（证据绑定）
- 证据包: `/app/data/evidence/finding-<id>/`（`pack.json` + HMAC `pack.seal.json`）
- 触发包: `cases/<case>/request.txt` → `<case>/response.body` sha256 `<...>`
- 对照包: `cases/<case>/control/*` sha256 `<...>`
- gate: `gate.json` `"ok": true`；verdict: `reproduced`

## References / Attachments
- <截图、请求响应、录屏>
- 独立复测证据包: `/app/data/evidence/finding-<id>/`（见技能 src-retest）
```

---

## 3. 定级（CVSS 3.1 速记）

| 维度 | 取值 | 提示 |
|---|---|---|
| AV | N/A/L/P | 网络可达最常见 |
| AC | L/H | 需要竞态/特殊条件才 H |
| PR | N/L/H | 需登录= L；需管理员= H |
| UI | N/R | 需受害者点击= R |
| S | U/C | 越出安全边界才 C |
| C/I/A | H/L/N | 影响机密/完整/可用 |

常见档位参考：
- **Critical**：无交互 RCE / 大规模账户接管 / 全量数据泄露。
- **High**：存储型 XSS / 任意账户接管 / 严重越权读写 PII。
- **Medium**：需一定条件的越权 / 反射型 XSS / SSRF 有回显。
- **Low**：信息泄露有限 / 需高权限才能触发。

> **定级要和 program 的赏金表对齐**，不要一律往高打。

### 3.1 定级校准：可达性 ≠ 影响（最常被降级的地方）

三家 triage 拒收/降级最集中的一句话是：**「reachable 不等于有影响」**。以下都不足以支撑 C/I/A：

| 你观察到的 | 它能证明 | 它**不能**证明 |
|---|---|---|
| 请求返回 200 | 端点可达 | 你能拿到不该拿的数据 |
| 去掉鉴权头也返回 200 | 缺鉴权 | 缺鉴权造成了什么后果 |
| 响应里有个看起来敏感的字段名 | 字段存在 | 字段里有真实敏感值 |
| 报错栈里有版本号 | 信息泄露（很弱） | 可利用的漏洞 |
| 能改自己的 `userId` | 参数可改 | 能改别人的 |
| 页面反射了输入 | 反射存在 | 脚本能执行（要 browser 证据） |

**正确的顺序**：先证明**影响**（读到谁的数据 / 越了什么权 / 执行了什么），再回去选 CVSS 向量。
不要先写 `C:H` 再找理由——那是自证。

**评分天花板由证据决定，不由漏洞类型名决定**（与 `submit_brief.py` 的 `impact_ceiling` 一致）：

| 证据形态 | 天花板 |
|---|---|
| 证明拿到他人 PII / 凭据 / 可接管账户 / 生产密钥 | critical–high |
| 证明可越权写入 / 管理员面板存储型 XSS / 内网可达 | high |
| 有回显的 SSRF、需条件的越权读、反射型 XSS | medium |
| 仅目录列表、仅版本号、仅安全头缺失 | low（安全头缺失 → 不提交） |

---

## 3.2 四段强制：Counterevidence / Confidence / Severity Change Conditions / Evidence Binding

这四段不是「写给别人看的礼貌」，而是**写给你自己看的自我反驳**。缺任何一段，报告按未完成处理。

1. **Counterevidence（反证）**——必须列出你**主动做过**的对照实验，以及它排除了哪种替代解释。
   - 只写「我复现了」不算反证。反证是「我**尝试证伪**，没成功」。
   - 典型：换成本人 ID 也返回 200 → 说明这个端点本来就不按用户隔离 → 你的越权结论要重写。
2. **Confidence（置信度）**——`high / medium / low`，并写清不确定点。
   - `high` 的前提是：gate ok + verdict reproduced + 对照可重复 + 无环境依赖。
   - 有任何一个「可能只是环境差异」，最多 `medium`；`low` 的报告不要提交。
3. **Severity Change Conditions（降级/升级条件）**——写明「什么证据会让我改分」。
   - 这一条能直接防住「自评虚高」：如果连你自己都写不出升级条件，说明你手上的证据就是当前这个档。
4. **Evidence Binding（证据绑定）**——把报告里的每个数字/每个响应片段，指回证据包里的具体文件与 sha256。
   - 报告里出现的任何响应正文，都必须能在 `cases/*/response.body` 里按 sha256 找到；找不到 = 幻觉。

> 反证、置信度、降级条件三者的共同作用：让「我猜的」和「我验过的」在纸面上**物理分开**。三家里被判 hallucination 的报告，几乎都能在某一栏找到「没做对照、却写了高影响」。

### 3.3 机械校验（写完必跑）

四段是文本要求，光写进模板挡不住跳过。跑一次：

```bash
python3 /app/skills/src-retest/scripts/report_check.py \
  --report draft.md --finding-id <id> --task-id <id> \
  --kind <vulnclass> --host <host> --path <path>
```

它检查：四段是否都在、反证里有没有真对照、置信度是不是 low、证据包 HMAC 是否有效、
`gate.payload.ok` 与 `verdict=reproduced`、Evidence Binding 里的 sha256 能否在 `pack.json` 找到、
是否撞重复、是否靶场。**退出码 1 = 不可提交**，按它列出的问题逐条修，不要绕过。

---

## 4. 常见拒收 / 降级原因（务必规避）

- ❌ 复现步骤不完整、无法复现。
- ❌ 影响描述夸大（说 RCE 实际只是 XSS）。
- ❌ out-of-scope 资产，或用了禁止的测试方式（未授权扫描）。
- ❌ 无实质影响的「理论漏洞」（缺 PoC）。
- ❌ 自评等级虚高，与 program 赏金表不符。
- ❌ 重复提交（提交前先看 Hacktivity / 已知问题）。
- ❌ 使用真实用户数据（应自建测试账号，最小化验证）。
- ❌ 把 Juice Shop / CTF / 教学靶场交到三家 SRC。
- ❌ 只有 AI 口述、没有独立证据包（`src-retest` 未过）。
- ❌ 把非洞当洞：缺安全头、版本泄露、用户名枚举、Self-XSS、SPA fallback 200、评分越界无资金影响（见 `src-triage`）。
- ❌ 复测结论是 `not_a_vuln` / `inconclusive` 仍写成可提交报告。
- ❌ 同一根因交两次（duplicate）。

---

## 5. 提交前自查（含独立复测门禁）

**写完报告不等于能交。** 顺序：`src-triage` → `src-retest` → 本技能。

- [ ] `src-triage` 判定是 `candidate`（不是 drop / needs-human）
- [ ] 已用 `http_evidence_record` + `http_evidence_compare` 留下 attack/control 原始包（磁盘上的 `response.body` / sha256，不是 AI 口述）
- [ ] compare 带 `attack_contains` 或 `json_path`（纯状态码对照不算）
- [ ] `retest_strict_gate` 写出 `gate.json` 且 `"ok": true`（attack 正文含 victim_marker，control 不含）
- [ ] XSS 已用 `browser_xss_evidence`，`dialog_executed=true` 且有截图
- [ ] 数字（用户数、金额）以本次证据包为准，未抄旧报告
- [ ] `verdict.json` 为 `reproduced`（由 `retest_verdict` 写入；`not_a_vuln` / `inconclusive` / `fixed` 都不写提交稿）
- [ ] `submit_advice` 不是 `never`（Juice Shop / CTF / 故意靶场 / 非洞 → 永远 never）
- [ ] `ready` 仅当存在 HMAC `signoff.json`（用户亲口口令 **加上** `gate.challenge`）；否则最多 `needs-human`
- [ ] 目标在 **你已加入且 accepted** 的 in-scope 内
- [ ] 步骤可原样复现，含完整请求/响应
- [ ] 影响真实且不夸大，有 PoC；定级按**本次证据里的影响**，不按漏洞类型名往高打
- [ ] **Counterevidence** 已写：列出主动做的对照实验 + 被排除的替代解释
- [ ] **Confidence** 已写：high/medium/low + 不确定点（low 不提交）
- [ ] **Severity Change Conditions** 已写：升级条件与降级条件
- [ ] **Evidence Binding** 已写：报告里每个响应片段都能在 `cases/*/response.body` 按 sha256 找到
- [ ] `report_check.py` 退出码 0（四段 + HMAC + gate + verdict + 绑定 + 判重 + 靶场全过）
- [ ] 已跑 `dup_check.py --task-id T --kind K --host H --path P`，退出码 0（无重复候选）
- [ ] 已跑 `scope_check.py --task-id T --url <url>`，退出码 0（在 scope 内）
- [ ] 报告里没有「reachable 就写 C:H」式的自证（见 3.1 表）
- [ ] 等级与 CVSS 与 program 赏金表一致
- [ ] 已排除重复（Hacktivity + `search_finding_duplicates`）
- [ ] 未使用真实用户数据 / 未造成破坏
- [ ] 语言符合 program 要求

`retester` 结论以证据包里的 `verdict.json` 为准（reproduced / not_a_vuln / fixed / inconclusive），不改原报告。没有 `gate.json` ok、没有证据包路径、或 verdict 不是 reproduced 的报告，按不可提交处理。`ready` 没有 `signoff.json` 同样不可提交。
