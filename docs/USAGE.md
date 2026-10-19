# XFSRC — 使用场景与合规边界

## 这是什么

XFSRC 是 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 的**个人私有 fork**，在上游基础上做安全加固与工作流定制，用于**海外授权漏洞赏金（SRC）**场景。

## 授权平台

本仓库的流程、技能与工具链针对以下三家平台设计：

| 平台 | 地址 |
|---|---|
| HackerOne | https://www.hackerone.com/ |
| Intigriti | https://www.intigriti.com/ |
| Bugcrowd | https://www.bugcrowd.com/ |

## 合规边界（使用前必读）

1. **只测已授权资产**。每个任务必须先在 `task_scope` 登记范围，且只使用 `manual`（人工确认）或 `goals`（目标拆解）来源的条目作为授权依据。
2. **本 fork 默认开启发请求前的授权闸**（`scope_gate_enabled=true`）：
   - 从工具参数与目标文件（`-l`/`-iL`/`cat FILE |`/`< FILE`）提取 host；
   - 未命中 `task_scope` 的调用直接阻断（fail-closed）；
   - 目标列表读不到时同样阻断。
3. **遵守各 program 的 policy**，尤其是：
   - 自动化扫描/爬虫是否允许；
   - 速率限制（本 fork 默认 ffuf `-rate 50`、katana `-rl 50`、nuclei `-rl 50`）；
   - 是否允许外部 OOB（Intigriti 多数禁止；本 fork 的 OOB 服务器可在 `/app/data/oob/config.env` 留空禁用）。
4. **不得使用本工具对未授权系统发起测试**。越界请求是三家平台封号的首要原因。
5. 本仓库不包含任何真实目标数据、凭据或证据；`data/`、`.env`、`jwt.key`、HMAC 密钥均已忽略。

## 分支模型

| 分支 | 内容 |
|---|---|
| `main` | 上游原样，用于 `git pull upstream` 同步 |
| `local` | 本地加固与定制（授权闸、工作区隔离、代理链、限流等） |

版本号格式：`<上游版本>-fix<N>`。带 `-fixN` 后缀的构建无法被页面「一键更新」覆盖，这是刻意设计。

## 同步上游

```bash
git fetch upstream
git checkout main && git merge --ff-only upstream/main
git checkout local && git rebase main   # 或 merge，视冲突而定
```

冲突通常集中在 `guard/`、`server/`、`db/`（本地改动最密集处）。

## 目录约定

| 路径 | 说明 |
|---|---|
| `agent/ db/ server/ guard/ intercept/ traffic/` | 核心代码（含本地修复） |
| `skills/src-*` | 面向 H1/Intigriti/Bugcrowd 的测试技能 |
| `deploy/` | 本地部署定制（compose、启动脚本、代理与保留策略），非上游功能 |
