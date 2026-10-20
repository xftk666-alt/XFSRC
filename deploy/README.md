# 本地部署定制（非上游功能）

这里的文件用于本机 Docker 部署，**不属于上游 ARTEX 的功能**。上游代码本身不依赖本目录。

## 文件

| 文件 | 作用 |
|---|---|
| `docker-compose.yml` | 在上游 compose 基础上增加：`start.sh`、`jwt.key`、`bin/artex` 只读挂载 |
| `start.sh` | 守护脚本，额外挂载 `restore_to_runtime.sh`、`proxy_sync.py`、`retention.sh` 三个钩子 |
| `scripts/proxy_sync.py` | 从 DB `global_proxy` 生成 `proxychains.conf` 与 `proxy.env` |
| `scripts/pc_run.sh` | 用 proxychains 包装不支持 HTTP 代理的工具（nmap 等） |
| `scripts/proxy_exec.sh` | 给 Go 工具注入原生代理参数（ffuf/katana/nuclei/dalfox/sqlmap/subfinder/gau/tlsx） |
| `scripts/run_naabu.sh` | naabu 原生 SOCKS5 代理 + 私网绕过 |
| `scripts/oobctl.sh` | interactsh OOB 管理（服务器/令牌从 `/app/data/oob/config.env` 读取，留空即禁用） |
| `scripts/retention.sh` | 数据保留：sessions/transcripts 30 天、聊天活动与日志 90 天；证据/任务/漏洞永不删除 |
| `scripts/restore_to_runtime.sh` | 容器重建后把 `skills/src-retest/runtime/` 快照恢复回 `/usr/local/share/artex-src` |

## 使用方式

compose 里的相对路径以 `deploy/` 为基准（`../data`、`../skills`、`../bin`），
因此在仓库根目录执行：

```bash
docker compose -f deploy/docker-compose.yml --env-file /path/to/.env up -d
```

`--env-file` 相对**当前工作目录**解析；也可以把 `.env` 直接放在 `deploy/` 下，此时无需该参数。

Compose 工程名固定为 `xfsrc`，容器为 `xfsrc-app` / `xfsrc-db`，数据卷为
`xfsrc_pgdata`，网络固定 `172.18.0.0/16`（宿主机转发服务只监听
`172.18.0.1:3066`，换网段会让容器失去出海口）。

或把 `deploy/docker-compose.yml`、`deploy/start.sh`、`deploy/scripts/` 复制到项目根目录后
按上游方式部署。

## 镜像

```bash
# 从仓库发布包解压出二进制后，构建或复用镜像：
docker tag xfsrc:<tag> xfsrc:latest
```

当前部署使用 `xfsrc:0.3.22-fix9`（基于官方 `ruoji6/artex` 加装扫描工具链与 proxychains）。

## 部署前提

1. 构建好的二进制放到 `bin/artex`（只读挂载到 `/app/artex`，页面一键更新无法覆盖）。
2. `data/jwt.key` 存在（避免容器重建后所有会话失效）。
3. 镜像内含扫描工具链（本仓库的 `artex-local` 镜像已固化 subfinder/httpx/katana/nuclei/ffuf 等）。

## 出口代理

```
容器 → 172.18.0.1:3066（宿主机 karing-docker-forward，仅 Docker 网桥可达）
     → Karing 127.0.0.1:3066 → 海外出口
```

- 私网/回环目标自动绕过代理（`net_env.sh`、`proxy_exec.sh`、`run_naabu.sh` 同一套判定）。
- 启动时 `proxy_sync.py` 从数据库读取 `global_proxy`，不需要手改配置。

## 数据保留

配置在 `/app/data/retention.env`：

```sh
RETENTION_ENABLED=1
RETENTION_SESSIONS_DAYS=30
RETENTION_TRANSCRIPTS_DAYS=30
RETENTION_CHAT_ACTIVITY_DAYS=90
RETENTION_SERVER_LOG_DAYS=90
RETENTION_DRY_RUN=0
```

手动执行（可加 `--dry-run`）：

```bash
docker exec artex-artex-1 /app/skills/src-retest/scripts/retention.sh --dry-run
```
