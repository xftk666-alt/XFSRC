---
name: src-graphql
description: 海外 SRC 授权范围内的 GraphQL 测试（内省、IDOR、批量、字段建议、深度限制）。当发现 /graphql、/gql 或前端有 __typename 时使用。内省与批量请求须先看 policy；禁止全 schema 爆破拖库。
---
# 海外 SRC：GraphQL

已授权。目标：弄清 schema 里**有对象 ID 的 query/mutation**，按 `src-idor` 的对照表测；不是把整个图拖下来。

配套：本技能 + `src-idor` → **`src-triage`（仅内省开启多数 Informative）** → `src-retest` → `src-report-writing`。

---

## 0. 合规

- [ ] endpoint in-scope
- [ ] 内省（`__schema`）有的 program 当信息泄露、有的允许；先 GET 一次，被拒就停
- [ ] 禁止用自动化跑几千条 mutation
- [ ] 批量（batch array）可能被当 DoS —— 只试 **2** 条证明能并成就够

---

## 1. 发现

```
ffuf_fuzz(url="https://in-scope/FUZZ", wordlist="/usr/local/share/wordlists/graphql.txt")
```

常见：`/graphql` `/api/graphql` `/gql` `/v1/graphql`。前端 JS 搜 `graphql` `__typename`。

---

## 2. 最小请求

1. 试内省：

```graphql
{ __schema { queryType { name } mutationType { name } } }
```

或 `GET ?query=`。若开着，再拉类型名（不要一次 dump 全字段到报告里）。

2. 关内省：用错误消息的 **字段建议**（少打几次）、前端 query 原文、`katana` 里的 operation 名。

3. 对每个 `user(id:)` `order(id:)` `node(id:)`：套 `src-idor` 对照表（A 的 token + B 的全局 ID）。GraphQL 常用 Relay 全局 ID（base64 `Type:123`），换 type 前缀试试 **一次**。

4. 批量：`[{query:...},{query:...}]` 两条。若一条失败不影响另一条且能读 B 的数据 → 写入报告。

5. 深度/递归：只证明能嵌套到异常深度 **一次**，不要打挂服务（DoS 常 OOS）。

---

## 3. 定级

内省开启 only → **默认 `src-triage` drop / Informative**（看 program 是否明文收）。GraphQL IDOR 按数据敏感度同 `src-idor`。未认证 mutation 能改数据 → High+。深度嵌套证明 DoS → 多数 OOS，不要报。

---

## 4. 工具

`ffuf_fuzz` + `graphql.txt`；`browser` MCP 从开发者工具抄 query；`src-idor` 对照。  
先 `src-triage`；candidate 才 `report_finding`（vulnclass=`graphql` 或 `idor`）→ `src-retest`
