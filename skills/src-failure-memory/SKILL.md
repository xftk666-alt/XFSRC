---
name: src-failure-memory
description: 失败记忆与跨任务继承：把「试过什么、为什么失败」写成可回灌的否定事实，避免新任务从零开始、重复踩同一个坑。含失败记录格式、跨任务继承（source_task_ids）约定、任务收尾归档规则。当任务开始（读历史失败）、某条线索被排除、或任务收尾时使用。
---
# src-failure-memory — 失败也是资产

## 问题

没有失败记忆时，每个新任务都会重做这些事：

- 再试一次「这个接口可能没鉴权」——上次已经证明有鉴权
- 再扫一遍同一个目录——上次已经 403
- 再猜同一个隐藏参数——上次 arjun 已经跑过
- 再换一个 payload 试同一个 WAF——上次已经确认全拦

**失败记录的价值不低于成功记录**，而且更便宜（不需要写报告）。

## 失败记录的格式（写进 `record_fact`）

```markdown
## FAILED: <一句话>
surface: <URL / 接口 / 功能点>
vuln_class: <taxonomy 类名>
attempted:
  - <具体动作 1>  → <结果>
  - <具体动作 2>  → <结果>
why_it_failed: <机制解释，不是"没成功">
scope_of_conclusion: <只对这条路径成立 / 对整个端点成立 / 对整个域名成立>
revisit_if: <什么条件变化时值得重试>
evidence: <证据包路径或命令输出摘要>
```

关键字段是 **`scope_of_conclusion`**：失败结论的作用域必须写清楚。
「`/api/users/1002` 有鉴权」≠「`/api/users/*` 都有鉴权」。
把局部失败当成全局结论，是比不记录更糟的错误。

## 什么时候必须记

1. 一个候选被判定 `ruled_out`（`src-closure` 要求）
2. 一个 payload 族试了 3 次无差异
3. 一个端点明确返回 403/404 且不是可绕过的
4. 一个工具在某目标上不可用（WAF 拦、超时、协议不支持）
5. 一个假设被区分性探针排除（`src-hypothesis`）

## 跨任务继承

新建子任务时：

```python
spawn_task(
  description="<新目标>",
  goal="...",
  source_task_ids=["<旧任务id>"],   # 只读继承已探明的资产与结论
)
```

继承的是**事实与资产**，不是「上次的结论一定成立」。
新任务的 policy/scope 可能不同，**失败结论要重新确认作用域**。

## 任务收尾归档

任务结束前，把失败记录整理成一段：

```markdown
## Negative Results (for future tasks)
| surface | class | conclusion | scope | revisit_if |
|---|---|---|---|---|
| /api/users/{id} | idor | 有对象级鉴权 | 仅该端点 | 若发现新身份/新版本 API |
| api.example.com | dir-brute | common.txt 全 403 | 该 host | 若拿到更高权限 |
```

写进任务的最终 fact，并在 `src-coverage` 里对应记 `ruled_out`（带 evidence）。

## 铁律

1. **「没找到证据」不是「不存在」**。信息缺失记 `open_proof_gap`，不要记 `ruled_out`。
2. **失败结论必须带作用域**。没有作用域的失败记录会误导下一个任务。
3. **不要复用别人的失败结论**。跨任务继承时重新确认 scope/policy 是否一致。
4. **失败记录也要有证据**。至少要有「请求 + 响应」或「命令 + 输出」。
5. **收尾必须归档**。留在会话里等于丢失。
