---
name: src-roe-parser
description: RoE / program policy 解析与约束落地：把 HackerOne/Bugcrowd/Intigriti 的 policy 页面或 PDF 转成结构化的 allowed/forbidden/rate-limit/excluded，写入 task_scope 与 set_constraints，让 scope_check 与后续工具自动遵守。用于新建任务、加入新 program、policy 更新、或不确定某项测试是否允许时。
---
# src-roe-parser — 把 policy 变成机器可执行的约束

## 为什么这是第一优先级

海外 SRC 唯一不可逆的错误是**对 out-of-scope 发请求**。
而 out-of-scope 的定义不只在资产列表里，还在 policy 的**文字条款**里：

- 「禁止自动化扫描」→ 你的 httpx/ffuf/nuclei 全部不能用
- 「限速 5 req/s」→ 超了就是滥用
- 「排除 `*.staging.example.com`」→ 资产列表里有，但明确排除
- 「不要测试第三方 SaaS（Zendesk/Salesforce/Shopify…）」→ CNAME 过去的子域不能碰
- 「禁止 DoS / 禁止访问真实用户数据」→ 某些 payload 与验证方式直接违规

**读漏一条 = 账号终止。** 所以这一步必须是结构化的、可复查的，不能靠"我读过 README"。

## 输入

- program 的 policy 页面（HTML/Markdown 文本）
- 或 policy PDF
- 或 `h1_scope` / `bugcrowd_scope` / `intigriti_scope` 返回的 scope 摘要

## 输出（必须落到两处）

### 1. `task_scope`（授权边界，scope_check 读它）

每个 in-scope 条目一条：
- `root_domain` / `subdomain` / `url` / `ip` / `cidr`
- **不要**把 out-of-scope 的写进来
- 有通配符时保留通配符语义

### 2. `set_constraints`（行为约束）

```json
{
  "program": "example-h1",
  "platform": "hackerone",
  "policy_url": "...",
  "automation": "prohibited | allowed | requires_notification",
  "rate_limit_rps": 5,
  "max_threads": 5,
  "forbidden": [
    "denial_of_service",
    "social_engineering",
    "physical",
    "third_party_saas_testing",
    "accessing_real_user_data",
    "automated_scanning"
  ],
  "excluded": ["*.staging.example.com", "legacy.example.com"],
  "credential_policy": "test_accounts_only",
  "data_handling": "no_exfiltration_no_retention",
  "disclosure": "coordinated_90d",
  "notes": "原文引用：..."
}
```

## 解析清单（逐条打勾，不许跳）

拿到 policy 后，按这个顺序抽：

- [ ] **1. In-scope 资产**：域名/IP/App/API/移动端。注意「wildcard 是否包含子域的子域」。
- [ ] **2. Out-of-scope 资产**：明确列出的排除项 + 「所有不在列表内的资产」这类兜底条款。
- [ ] **3. 自动化政策**：是否允许扫描器？是否要求提前通知？是否只允许人工？
- [ ] **4. 速率限制**：具体 rps / 并发数 / 每日请求量。
- [ ] **5. 禁止的测试类型**：DoS、社工、物理、钓鱼、访问真实用户数据、修改/删除数据、上传 webshell 到生产。
- [ ] **6. 第三方依赖**：SaaS、CDN、支付网关、邮件服务 —— 通常都不在 scope。
- [ ] **7. 账号要求**：必须自建测试账号？能否用他人账号做越权验证（通常只允许"读取证明"，不允许导出）。
- [ ] **8. 数据处理**：发现的 PII/凭据如何处理？能否留存截图？保留多久？
- [ ] **9. 披露条款**：协调披露期限、能否公开写博客。
- [ ] **10. 重复/已知问题**：是否有 "known issues" 列表（报了也不算）。

## 落库动作

```python
# 1) 先写 scope（不写 scope，后面所有请求都是越界）
add_task_scope(task_id="<id>", ...)   # 逐条

# 2) 再写约束
set_constraints(task_id="<id>", constraints={...})

# 3) 抽查：用 scope_check 验证
scope_check(task_id="<id>", url="https://in-scope.example.com/")
scope_check(task_id="<id>", url="https://out-of-scope.example.com/")   # 必须 out-of-scope
```

## 硬规则

1. **policy 没读到 = 不许开工。** 不要用「行业惯例」推断。
2. **兜底条款优先**：「未列出的资产一律 out-of-scope」比任何白名单都强。
3. **CNAME 到第三方 = 默认 out-of-scope**，除非 policy 明确说客户侧配置可测。
4. **约束冲突时取最保守**：policy 说允许但平台 ToS 禁止 → 不做。
5. **policy 变更要重跑**：加入 program 后 policy 可能改；每次新任务重新确认一次。
6. **原文引用**：`notes` 里保留关键条款原文，便于事后自证「我当时按 policy 做的」。

## 与其他 skill 的关系

```
src-roe-parser（能不能测、怎么测）
   ↓
src-scope-guard（每次请求前再查一遍）
   ↓
src-taxonomy（该测什么）→ src-coverage（测了没）
```
