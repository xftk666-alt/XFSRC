#!/bin/bash
# 一键发版：提交 → 打标签 → 推送 → GitHub Actions 自动构建发布。
#
# 用法：
#   ./scripts/release.sh                  # 版本号自动在最后一个 tag 上 +1
#   ./scripts/release.sh 0.3.22-fix13     # 指定版本（不带 v 前缀）
#   ./scripts/release.sh --no-push        # 只提交和打标签，不推送
#
# 前提：
#   - 在仓库根目录执行
#   - 已配置 origin（git remote -v 可见 xftk666-alt/XFSRC）
#   - 本机访问 GitHub 需要代理时，脚本会自动为本次推送启用 HTTP_PROXY
#
# 推送后约 2.5 分钟，GitHub Actions 会创建 Release 并上传 5 个平台的 zip。
set -euo pipefail

cd "$(dirname "$0")/.."

PROXY="${XFSRC_GIT_PROXY:-http://127.0.0.1:3067}"
PUSH=1
VERSION=""

for arg in "$@"; do
  case "$arg" in
    --no-push) PUSH=0 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "未知参数：$arg" >&2; exit 2 ;;
    *) VERSION="$arg" ;;
  esac
done

die() { echo "错误：$*" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "不在 git 仓库内"
git remote get-url origin >/dev/null 2>&1 || die "没有 origin remote"

# 版本号：未指定时取最新 tag 的 fix 号 +1
if [ -z "$VERSION" ]; then
  last=$(git tag -l 'v*' --sort=-v:refname | head -1)
  [ -n "$last" ] || die "没有可参考的标签，请显式指定版本，例如 0.3.22-fix13"
  if [[ "$last" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-fix([0-9]+)$ ]]; then
    VERSION="${BASH_REMATCH[1]}-fix$((BASH_REMATCH[2] + 1))"
  elif [[ "$last" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
    VERSION="${BASH_REMATCH[1]}-fix1"
  else
    die "无法从 $last 推导下一个版本，请显式指定"
  fi
fi

TAG="v${VERSION}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-fix[0-9]+)?$ ]] || die "版本格式无效：$VERSION（应形如 0.3.22-fix13）"
git rev-parse "$TAG" >/dev/null 2>&1 && die "标签 $TAG 已存在"

# 1) 提交
if [ -n "$(git status --porcelain)" ]; then
  echo "[1/4] 提交改动"
  git add -A
  git commit -m "release: $TAG"
else
  echo "[1/4] 工作区干净，跳过提交"
fi

# 2) 打标签
echo "[2/4] 打标签 $TAG"
git tag -a "$TAG" -m "$TAG"

if [ "$PUSH" = "0" ]; then
  echo "[3/4] --no-push，已跳过推送"
  echo "      手动推送：git push origin $(git branch --show-current) $TAG"
  exit 0
fi

# 3) 推送（本机直连 GitHub 常超时，统一走代理）
BRANCH=$(git branch --show-current)
echo "[3/4] 推送分支 $BRANCH 与标签 $TAG（经 $PROXY）"
git -c http.proxy="$PROXY" push origin "$BRANCH"
git -c http.proxy="$PROXY" push origin "$TAG"

# 4) 提示
echo "[4/4] 已推送。GitHub Actions 将自动构建并发布："
echo "      https://github.com/$(git remote get-url origin | sed -E 's#.*github.com[:/]([^/]+/[^/.]+)(\.git)?#\1#')/actions"
echo "      约 2.5 分钟后 Release 可见；之后在实例的「系统 → 设置 → 版本与更新」点检查更新即可升级。"
