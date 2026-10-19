---
name: src-deserialization
description: 反序列化与解析器类漏洞的被动识别：先通过技术栈、错误栈、序列化格式特征判断目标是否使用 Java/Jackson/FastJSON/XStream/.NET/PHP/Python/Ruby 的易受攻击解析器，再决定是否值得深入。只做只读指纹与无害探针，不自动发送 gadget payload。当响应出现 base64 序列化串、Java 异常栈、PHP O: 对象串、或 JSON 深合并迹象时使用。
---
# src-deserialization — 被动识别优先，不盲打 payload

## 为什么先被动

反序列化漏洞（Java gadget chain、PHP object injection、.NET BinaryFormatter、Python pickle）
是 $$$–$$$$ 级别，但**盲打 payload 的风险极高**：

- 可能触发 RCE → 破坏生产数据（违反绝大多数 policy）
- 可能被 WAF 记录为攻击 → 封号
- 误报率极高（base64 不等于序列化）

正确顺序：**识别 → 确认格式 → 只读探针 → 才考虑最小验证**。

## 第一步：识别信号

| 信号 | 可能的技术 | 检查方式 |
|---|---|---|
| 响应/请求含 `rO0AB` 开头 base64 | Java 序列化 | 解码看 `\xac\xed\x00\x05` 魔数 |
| 响应含 `java.lang.*Exception` 栈 | Java | 记录类名与版本 |
| `{"@type":"..."}` / `@class` 字段 | Jackson 多态 | 检查是否接受任意类名 |
| FastJSON 特征（`{"@type":"java.lang.AutoCloseable"}`） | FastJSON | 版本 < 1.2.83 才有已知链 |
| `O:8:"stdClass"` / `a:2:{...}` | PHP serialize | 找 unserialize 入口 |
| `AAEAAAD/////` | .NET BinaryFormatter | 罕见但高价值 |
| `gASV` / `\x80\x04\x95` | Python pickle | 找 pickle.loads 入口 |
| `_rails` / Marshal base64 | Ruby | 找 Marshal.load |
| `__type` / `$type` | .NET JSON.NET TypeNameHandling | 检查是否 AllowedTypes 未限制 |
| ViewState `__VIEWSTATE` | ASP.NET | 检查 MAC 是否启用 |

## 第二步：只读探针（安全）

允许的探针：

- 请求一个**格式错误**的序列化串，看是否返回解析错误（暴露解析器类型与版本）
- 请求一个**合法但无副作用**的对象（如只读查询）
- 观察错误消息里的类名（Jackson/FastJSON 常泄露完整类路径）

**禁止**：

- 发送真实 gadget chain payload
- 触发 DNS/HTTP 回连（除非用自建 OOB 且 policy 允许）
- 尝试写入文件或执行命令

## 第三步：判断价值

只有同时满足才继续深入：

1. 确认存在反序列化入口（不是普通 JSON 解析）
2. 解析器版本落在已知受影响范围
3. 有已知 gadget 依赖（如 CommonsCollections、Spring、Groovy）
4. policy 允许做最小验证

否则记 `open_proof_gap` 并写清楚缺什么。

## 报告纪律

- **不要**把「响应里有 base64」当漏洞
- **不要**把「用了 Jackson」当漏洞
- 必须给出：入口点 + 可控字段 + 解析器版本 + 受影响证明
- 若只做到识别，写 `needs_follow_up`，不要报

## 与其他 skill 的关系

- 上游：`api-recon`（发现参数）、`src-info-disclosure`（错误栈）
- 本 skill：识别 → 只读探针 → 价值判断
- 下游：`src-hypothesis`（每个 gadget 假设配一个区分性探针）→ `src-closure`
