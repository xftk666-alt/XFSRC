# XFSRC 项目上下文（给 AI 助手 / 新会话）

本文件供 AI 编码助手在**新会话**中快速恢复上下文。人类读者可跳过。

## 这是什么

`xfsrc` 是 [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) 的**个人私有 fork**，
用于**海外正规授权的 SRC 漏洞挖掘**（HackerOne / Intigriti / Bugcrowd）。
AGPL-3.0。

## 分支模型

| 分支 | 内容 |
|---|---|
| `main` | 上游原样，仅用于 `git fetch upstream` 同步 |
| `local` | 全部本地改动（**实际部署与发版用这个**） |

版本号：`<上游版本>-fix<N>`，如 `0.3.23-fix1`。

## 相对上游的关键改动

- **授权闸**（`guard/scope*.go`、`db/scope_check.go`、`server/scope_gate.go`）：
  发请求前从工具参数与目标文件提取 host（含短写 IPv4、单标签 host:port），未命中
  `task_scope` 即阻断（fail-closed）。**挂在所有能跑 Bash/WebFetch 的 agent 上**：
  worker、planner、任务主 Agent，以及能反查到任务的 chat 会话（`agent/*.go`
  `SetHooks` + `server/task_llm.go`）。只信任 `manual` / `goals` 来源；
  `agent` / `auto` 仅用于覆盖度。`add_task_scope` 只给目标拆解器。
- **企业范围来源**（`company_scope.source`）：`task_scope.kind=company` 只展开
  `manual`/`goals` 写下的企业规则，模型工具写的是 `agent`（只用于归属与覆盖度）。
- **复测结论校验**（`evidence/verdict.go`）：`reproduced` / `fixed` 必须带
  `pack_dir`，服务端重算 HMAC 与证据指纹；`inconclusive` 不要求证据包。
- **工作区隔离**（`server/workspace.go`）：拒绝 `evidence/`、`traffic/`、`sessions/`、
  `transcripts/`、`jwt.key`；符号链接按解析后的真实路径二次校验，悬空链接直接拒绝。
- **拦截规则匹配面**（`guard/guard.go: ruleSubject`）：Write/Edit 只匹配 `file_path`。
- **兜底裁判失败策略**（`intercept/intercept.go: defaultJudgeFailAction`）：本 fork 默认
  `allow`。理由：授权边界是 fail-closed 的 scope 闸（先于拦截规则执行），内置破坏性
  规则也先于裁判；裁判只处理「没命中任何规则」的调用。无人值守下选 `ask` 会让每个
  受影响调用挂满 300 秒再被拒，看起来像卡死且没有安全收益。失败时会在会话流里发一条
  `judge_fallback` 活动（含错误原因），不会静默降级。需要更严可在「拦截审批」页改成
  `ask`/`deny`。
- **录制开关**（`traffic/traffic.go`）：关闭时存储层不落盘。
- **登录限流**（`server/auth_limit.go`）：10 次/分钟/真实客户端 IP（本机反代后取
  `X-Forwarded-For`，防单点锁死管理员）。
- **会话**（`server/auth.go`）：JWT 放 HttpOnly + SameSite=Strict cookie；
  `?token=` 只允许 SSE；登出与改密递增 `auth.token_version`，已签发令牌立即失效。
- **首启防抢注**：未设密码时生成一次性 setup token（日志 + `data/setup-token`），
  非回环来源的 `/api/auth/init` 必须携带。
- **私有仓库更新**（`selfupdate`）：`Repo = xftk666-alt/XFSRC`；
  私有仓库资产需走 REST API + `Accept: application/octet-stream`（`WithAPIAssets`）。
- **品牌**：系统名、登录用户名、banner 均为 `XFSRC`。

## 本地部署

| 项 | 值 |
|---|---|
| 目录 | `/home/xiaofan/xfsrc-deploy` |
| 容器 | `xfsrc-app`、`xfsrc-db` |
| 卷 | `xfsrc_pgdata` |
| 网络 | `xfsrc_default`，固定 `172.18.0.0/16`（宿主机转发只听 `172.18.0.1:3066`） |
| 端口 | `8787`（UI/API）、`127.0.0.1:8788`（录制代理） |
| 出口 | 容器 → `172.18.0.1:3066` → Karing → 海外 |

启动：`cd /home/xiaofan/xfsrc-deploy && docker compose up -d --no-build`

## 开发约定

- 构建需要 Go 1.26.3（`/tmp/goroot`，可能需重新下载 `https://dl.google.com/go/`）。
- 依赖走官方 `proxy.golang.org`，本机需经代理：`HTTPS_PROXY=http://127.0.0.1:3067`。
- 仓库根存在 `data/`（700 权限）时，`go test ./...` 会因目录遍历失败；
  用显式包列表（见 `README.md` 的「本地运行与测试」）。
- 测试需要 PostgreSQL：`ARTEX_PG_DSN=postgres://artex:artex@127.0.0.1:15432/artex_test?sslmode=disable`。
- `db` 包的部分测试依赖干净库，脏库会误报。

## 发版

```bash
./scripts/release.sh              # 自动 +1
./scripts/release.sh 0.3.22-fix13 # 指定
```

推送标签 → GitHub Actions 自动构建 5 平台并发布 Release（约 2.5 分钟）。
详见 `docs/RELEASE.md`。

## 不要做的事

- 不要改 `main` 分支（它必须等于上游）。
- 不要在 `local` 上直接 `git push --force`（用 `--force-with-lease`）。
- 不要把 `data/`、`.env`、`jwt.key`、`skills/src-retest/runtime/`、`bin/` 提交进仓库。
- 不要把 GitHub Token 写进代码或文档。
