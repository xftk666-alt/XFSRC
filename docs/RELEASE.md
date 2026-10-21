# 发布与更新

本文说明 XFSRC 的版本号规则、发版流程与在线更新机制。

## 版本号

格式：`<上游版本>-fix<N>`，例如 `0.3.23-fix1`。

- `<上游版本>` 表示基于哪个上游 ARTEX 版本；
- `fix<N>` 是本地修订序号，同一上游版本内单调递增。

比较规则（`selfupdate.parseVersion`）：

```
0.3.23-fix1 > 0.3.23 > 0.3.22-fix13 > 0.3.22-fix1 > 0.3.22
```

`dev`、`0.3.7-2-gabc1234` 这类带其他后缀的版本会被判为**不可比较**，从而禁用一键更新——避免开发构建被正式版覆盖。

## 发版

### 一键

```bash
cd /home/xiaofan/xfsrc
./scripts/release.sh                # 自动在最新标签上 +1
./scripts/release.sh 0.3.23-fix1    # 或显式指定
```

脚本做四件事：提交 → 打标签 → 推送分支与标签 → 提示 Actions 地址。

**发版前必须在 `CHANGELOG.md` 写一节 `## v<版本>`**（例如 `## v0.3.23-fix1 — …`）。
`release.yml` 会把这一节原样作为 Release 正文；`scripts/release.sh` 在打标签前就会
检查它存在，缺了直接报错退出，避免发出一个没有任何说明的版本。

### 手动

```bash
git add -A && git commit -m "fix: ..."
git tag -a v0.3.23-fix1 -m "0.3.23-fix1: 说明"
git push origin local v0.3.23-fix1
```

推送标签即触发 `.github/workflows/release.yml`。

Release 正文的来源顺序：

1. `CHANGELOG.md` 里 `## v<版本>` 这一节（推荐，脚本会强制）；
2. 找不到时正文会显式标注「未找到 CHANGELOG 章节」，不会假装有说明。

## Actions 流水线

```
prepare   校验标签格式 → 锁定 commit
   ↓
frontend  npm ci + 静态导出（一次）
   ↓
binaries  5 个平台并行：linux/amd64、linux/arm64、
          darwin/amd64、darwin/arm64、windows/amd64
   ↓
release   汇总 zip → 生成 SHA256SUMS → 创建 Release（草稿→发布）
```

耗时约 2.5 分钟。失败时可在 Actions 页面手动 Run workflow 并指定已存在的标签。

标签必须匹配 `^v\d+\.\d+\.\d+(-fix\d+)?$`。

## 在线更新

实例 → **系统 → 设置 → 版本与更新**：

1. **更新代理**：容器内需填 `http://172.18.0.1:3066`（宿主机转发端口）。
2. **GitHub Token**：仓库是 private，`/releases/latest` 未认证会返回 404。
   生成 Fine-grained Token 时只需勾选本仓库的 **Releases: Read-only**。
3. 点「检查更新」→ 有新版则点「立即更新」。

更新流程：下载 → 比对 `SHA256SUMS` → 解压 → 写入 `artex.new` → 退出码 75 → `start.sh` 拉起 → 新版本稳定后确认，旧版保留为 `artex.old`。

连续 3 次启动失败会自动回滚到 `artex.old`。

## 部署位置

| 项 | 路径 |
|---|---|
| 程序二进制 | `bin/artex`（可写挂载到容器 `/app/bin`） |
| 上一版本 | `bin/artex.old` |
| 数据 / JWT 密钥 | `data/`（挂载到 `/app/data`） |
| 技能 | `skills/`（挂载到 `/app/skills`） |

镜像只提供运行时（扫描工具链、proxychains 等），程序本体由 `bin/` 挂载，因此更新不需要重建镜像。
