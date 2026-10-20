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

版本号：`<上游版本>-fix<N>`，如 `0.3.22-fix12`。

## 相对上游的关键改动

- **授权闸**（`guard/scope*.go`、`db/scope_check.go`、`server/scope_gate.go`）：
  发请求前从工具参数与目标文件提取 host，未命中 `task_scope` 即阻断（fail-closed）。
  只信任 `manual` / `goals` 来源；`agent` / `auto` 仅用于覆盖度。
- **工作区隔离**（`server/workspace.go`）：拒绝 `evidence/`、`traffic/`、`sessions/`、
  `transcripts/`、`jwt.key`，并做符号链接二次校验。
- **拦截规则匹配面**（`guard/guard.go: ruleSubject`）：Write/Edit 只匹配 `file_path`。
- **录制开关**（`traffic/traffic.go`）：关闭时存储层不落盘。
- **登录限流**（`server/auth_limit.go`）：10 次/分钟/IP。
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
