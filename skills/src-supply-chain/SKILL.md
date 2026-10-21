---
name: src-supply-chain
description: 供应链与依赖漏洞测试：从前端 JS/仓库拿到 manifest 或依赖版本，用 OSV 查已知漏洞，判断是否可达并写出符合 SRC 要求的报告。覆盖依赖混淆、已知 CVE 在目标上的可达性证明、以及"版本旧不等于可利用"的定级纪律。当目标有公开前端 bundle、GitHub 仓库、或 JS 里暴露依赖版本时使用。
---
# src-supply-chain — 依赖漏洞与供应链

## 合规红线（先读这条）

- 只处理**已授权**资产：目标必须先在 `task_scope` 登记，且 `scope_check` 返回 in-scope。
- 每个 program 的 `policy` 可能禁止自动化/限速/外部 OOB；按 policy 调整，不按习惯。
- 拿不到 in-scope 结论时**不发请求**，先回 `src-roe-parser` 补范围。



## 为什么这类容易误报

SRC 里被大量拒收的报告形态：

> 「目标的 jQuery 是 1.12.4，存在 CVE-XXXX，请修复。」

这**不是漏洞**，是版本信息。要成为有效报告，必须证明：

1. 该版本**确实**受该 CVE 影响（版本范围正确）
2. 有**可达的代码路径**（目标实际调用了受影响的 API）
3. 攻击者能**控制输入**到达该路径
4. 造成**实际影响**（不是理论上可能）

缺任一条 → 只能记 `informational` 或 `needs_follow_up`。

## 步骤

### 1. 拿依赖清单

| 来源 | 方法 |
|---|---|
| 前端 bundle | `jsluice_scan` 抽 URL/密钥；`browser_evaluate` 读 `window.jQuery.version`、`angular.version`、`__NEXT_DATA__` |
| 公开仓库 | GitHub 搜索组织/项目，读 `package.json` / `requirements.txt` / `go.mod` |
| 报错页 | 栈追踪常暴露框架版本 |
| HTTP 头 | `X-Powered-By`、`Server`（只作线索） |

### 2. 查漏洞

```python
osv_check(file="/path/package.json")
osv_check(package="lodash", ecosystem="npm", version="4.17.20")
```

### 3. 判可达性（关键）

按框架分别确认：

- **前端库**（jQuery/Angular/React）：受影响的 API 是否被页面调用？用 `browser_evaluate` 检查 DOM sink、`$.html()` 调用点。
- **服务端库**：能否通过请求触发？看响应特征（错误栈、序列化格式）。
- **构建期依赖**：通常**不可利用**（不进入运行时），只能报 supply-chain 类 informational。

### 4. 依赖混淆（dependency confusion）

仅当目标有**私有包名**且公开 registry 上可注册同名包时才成立。验证方式：
- 在公开 registry 查该包名是否存在（存在且非官方 → 可能被抢注）
- **不要真的发布恶意包**（违法且违反 ToS）
- 结论只能到「存在抢注风险」，不能声称已利用

## 定级参考

| 情形 | 定级 |
|---|---|
| 已知 CVE + 可达 + 可控制输入 + 实际影响 | 按 CVE 本身的 CVSS，通常 high/critical |
| 已知 CVE + 可达 + 影响有限（信息泄露） | medium |
| 已知 CVE + 不可达 | informational / 不报 |
| 仅版本旧，无法证明影响 | **不报** |
| 依赖混淆（仅存在风险） | low / informational |

## 证据要求

- manifest 或版本来源（截图/响应片段）
- OSV 查询结果（含 CVE/GHSA 号）
- **可达性证明**：调用点、可控输入、实际响应差异
- 若不可达，明确写「已确认不可达，原因是 X」

## 与其他 skill 的关系

- 上游：`api-recon`（找 JS）、`src-recon-pipeline`（找仓库）
- 本 skill：依赖 → 漏洞 → 可达性
- 下游：`src-hypothesis`（可达性就是 H1/H2 的区分性探针）→ `src-closure`

## 铁律

1. **版本旧 ≠ 漏洞**。没有可达性证明不要报。
2. **不要为了验证而发布恶意包**。
3. **构建期依赖默认不可利用**，除非能证明进入产物。
4. **OSV 结果只是候选**，必须人工核对版本范围与受影响函数。
