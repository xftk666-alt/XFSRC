---
name: src-taxonomy
description: 海外 SRC 漏洞分类学与选题决策表（20 族 / 328 类，带 P 级、赔付档、CWE、检测手段、我方可复用技能与工具、证据要求、decision）。用于开工前确定"这个 program 该测哪些类"、收尾时反推"漏了哪些类"，以及把覆盖台账从"已测什么"升级为"应测什么 vs 实测什么"。当新建任务、做测试计划、判断优先级、或准备宣布任务完成时使用。
---
# src-taxonomy — 漏洞分类学与选题决策表

## 合规红线（先读这条）

- 只处理**已授权**资产：目标必须先在 `task_scope` 登记，且 `scope_check` 返回 in-scope。
- 每个 program 的 `policy` 可能禁止自动化/限速/外部 OOB；按 policy 调整，不按习惯。
- 拿不到 in-scope 结论时**不发请求**，先回 `src-roe-parser` 补范围。



## 为什么需要它

`src-coverage` 只能回答「我测过什么」，回答不了「**我应该测什么、漏了什么**」。
没有全集，覆盖台账就是自证清白；有了全集，才能算出缺口并按赔付排序。

数据源：`taxonomy.csv`（同目录，328 条，20 个族），字段：

| 字段 | 含义 |
|---|---|
| family | 族（1..24，对应 OWASP/VRT 分组） |
| vuln_class | 具体漏洞类 |
| priority | P1..P5（P1 最高影响） |
| payout | $ .. $$$$$（典型赔付档） |
| cwe | CWE 编号 |
| detect_how | 怎么发现（原文要点） |
| our_skill | 本平台对应 skill |
| our_tools | 本平台可调用工具 |
| evidence_required | 该类报告必须给出的证据形态 |
| decision | covered / partial / backlog / do_not_report |
| gap_note | 已知缺口 |

## 三种用法

### 1. 开工前：选题（10 分钟）

```bash
# 看某族有哪些类
python3 - <<'PY'
import csv
rows=[r for r in csv.DictReader(open('/app/skills/src-taxonomy/taxonomy.csv')) if r['family'].startswith('14.')]
for r in rows: print(f"{r['priority']:6s} {r['payout']:6s} {r['vuln_class']}  -> {r['our_skill']}")
PY
```

选题规则（按顺序）：

1. **先排除** `decision=do_not_report`（第 24 族：常见 informational）。
2. **先做 P1 + `$$$` 以上**，且 `our_skill` 不是 `(缺)` 的类。
3. **再看目标特征**：有 GraphQL → 第 3 族；有 SSO → 第 5 族；有上传 → 第 15 族；有 AI 功能 → 第 6 族（当前 backlog，只能手工）。
4. **同一 surface 至少覆盖 2 个不同族**，避免在单一类上反复消耗。

### 2. 收尾前：算缺口

```bash
python3 /app/skills/src-taxonomy/scripts/taxonomy_gap.py --task-id <id>
```

输出三类：
- **未覆盖**：`decision=covered` 且本任务 scope 相关，但 `coverage.json` 无记录
- **部分覆盖**：`decision=partial`
- **主动放弃**：`decision=backlog|do_not_report`（必须有 note）

只有「未覆盖」清零（或有 ruled_out/not_applicable 记录）才允许宣布 clean。

### 3. 写报告前：对证据形态

按 `evidence_required` 检查：是否只是 200？是否有多身份对照？是否有实际影响？
`src-report-writing` 的四段校验会拒绝「只有请求成功、没有影响证明」的报告。

## 硬规则

1. **`decision=covered` 不等于「一定测」**。它表示「有技能+工具有能力测」。是否测由 scope 与目标特征决定。
2. **`backlog` 类不得在报告里声称已覆盖**。要么 `needs_follow_up`，要么 `not_applicable` + 理由。
3. **`do_not_report` 类**（缺 header、self-XSS、仅 banner 泄露等）只在能证明实际影响时才报，否则记 `ruled_out`。
4. **优先级不是唯一依据**：P5 但 `$$$$$` 的类（如公开仓库密钥）可能比 P2 但 `$` 的更值得做。
5. 族编号对应本文件的 `family` 前缀；引用时写 `14. Broken Access Control` 而不是只写 14。

## 与其他 skill 的关系

```
src-taxonomy（应测什么）
   ↓
src-coverage（实测什么 / 缺口）
   ↓
src-hypothesis（每个候选怎么证伪）
   ↓
src-closure（三态收敛）
   ↓
src-report-writing + report_check（能不能提交）
```

## 更新方式

`taxonomy.csv` 是数据文件，可直接编辑。新增类时保持字段完整；`decision` 变更要写 `gap_note` 说明原因。
重新生成（从上游 PDF）：`python3 /app/data/sessions/conv-91/tools/build_taxonomy.py <coverage.txt> taxonomy.csv`（脚本含族→技能映射表，改映射请改脚本里的 `ASSET_MAP`）。
