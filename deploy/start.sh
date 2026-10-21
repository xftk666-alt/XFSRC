#!/bin/sh
# ARTEX 守护启动脚本（Linux / macOS / Docker ENTRYPOINT）
#
# 用法：
#   ./start.sh                       前台运行（Ctrl-C 停止）
#   nohup ./start.sh >artex.log 2>&1 &   后台常驻
#   ./start.sh -addr :9000           额外参数原样透传给 artex
#
# 它只做一件事：把 artex 跑起来，进程退出后按退出码决定要不要再拉起。
#
#   0      用户正常停止        → 退出循环
#   75     程序请求重启        → 立刻重跑（页面点了"一键更新"或"回滚"）
#   其他   崩溃                → 退避后重跑（1→2→4…最多 60 秒）
#
# 刻意不在这里做下载、SHA256 校验或换装：那些逻辑在 sh 和 bat 上要写两套，
# 而它们恰恰是最不能出错的一环——一旦换上跑不起来的二进制，本脚本会忠实地
# 反复拉起它，用户只能上机器手工救。所以校验/换装全部留在 Go 里（selfupdate 包），
# 由 artex 自己在启动时完成，脚本保持傻瓜化。
set -u

cd "$(dirname "$0")" || exit 1

# JWT 签名密钥必须在 /app/jwt.key（keyDir = 可执行文件所在的 /app）。容器重建会
# 丢掉镜像可写层，所以把它持久化在数据卷里，启动时恢复；首次启动则生成一个
# 32 字节（64 hex）的密钥。注意：/app 下的 jwt.key 绝不能是目录——Docker 对不存在
# 的绑定挂载源会创建目录，那会让 artex 读到 EISDIR 直接退出。
ensure_jwt_key() {
	keyfile=/app/jwt.key
	persist=/app/data/jwt.key
	mkdir -p /app/data 2>/dev/null || true
	if [ -d "$keyfile" ]; then
		# 之前误挂成目录：清掉（空目录才删，避免误删真实数据）
		rmdir "$keyfile" 2>/dev/null || { echo "[xfsrc] /app/jwt.key 是目录且非空，请手工处理" >&2; return 1; }
	fi
	if [ -s "$keyfile" ]; then
		# 容器内的 key 存在 → 反向同步回数据卷，保证重建后仍是同一把
		if [ ! -s "$persist" ] || ! cmp -s "$keyfile" "$persist"; then
			cp -f "$keyfile" "$persist" 2>/dev/null || true
		fi
		return 0
	fi
	if [ -s "$persist" ]; then
		cp -f "$persist" "$keyfile"
	else
		umask 077
		head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$keyfile"
		cp -f "$keyfile" "$persist" 2>/dev/null || true
	fi
	chmod 600 "$keyfile" "$persist" 2>/dev/null || true
}



# 优先使用可写挂载的 bin/artex（页面一键更新会替换它），否则回退到镜像内的 ./artex。
if [ -x /app/bin/artex ]; then
	BIN=/app/bin/artex
else
	BIN=./artex
fi
[ -x "$BIN" ] || { echo "[xfsrc] 找不到可执行文件 $BIN" >&2; exit 1; }

ensure_jwt_key || exit 1

# 复测闸门脚本在 /app/skills（持久卷）。镜像层 /usr/local/share/artex-src 重建会回到出厂旧版。
# 启动时把加固脚本和 HMAC 密钥拷回去，避免只剩技能路径、运行时路径变松。
if [ -x /app/skills/src-retest/scripts/restore_to_runtime.sh ]; then
	/app/skills/src-retest/scripts/restore_to_runtime.sh || echo "[artex] src-retest restore 失败（非致命）" >&2
fi

# 出口代理：把 global_proxy 同步成 proxychains 配置，供 nmap 等不支持 HTTP
# 代理的工具使用；失败不阻塞启动。
if [ -x /app/skills/src-retest/scripts/proxy_sync.py ]; then
	python3 /app/skills/src-retest/scripts/proxy_sync.py || echo "[artex] proxy_sync 失败（非致命）" >&2
fi

# 数据保留：启动 2 分钟后跑一次，之后每 24 小时一次（配置见 /app/data/retention.env）。
if [ -x /app/skills/src-retest/scripts/retention.sh ]; then
	( sleep 120; while :; do /app/skills/src-retest/scripts/retention.sh; sleep 86400; done ) >>/app/data/retention.log 2>&1 &
fi

# LLM 空回复护栏：openai-responses/anthropic 的空 200 会被重试，仍空返回 422，
# 避免编排层把空输出标成 completed（「无文字总结」）。llm_profiles.base_url
# 已指到 127.0.0.1:18787/18788/18789，进程不在则模型全挂，必须随 artex 一起拉起。
GUARD_PID=0
start_empty_guard() {
	if [ -x /app/data/empty_guard/run.sh ]; then
		/app/data/empty_guard/run.sh >/app/data/empty_guard/run.out 2>&1 &
		GUARD_PID=$!
		echo "[artex] empty_guard 看门 pid=$GUARD_PID"
	else
		echo "[artex] 找不到 /app/data/empty_guard/run.sh（空回复护栏未启动）" >&2
		GUARD_PID=0
	fi
}
stop_empty_guard() {
	if [ "$GUARD_PID" -ne 0 ]; then
		kill -TERM "$GUARD_PID" 2>/dev/null || true
		# 再杀监听，避免旧实例占口
		if command -v pkill >/dev/null 2>&1; then
			pkill -TERM -f '/app/data/empty_guard/empty_guard.py' 2>/dev/null || true
		fi
		GUARD_PID=0
	fi
}

RESTART_CODE=75
MAX_DELAY=60

child=0
stopping=0

# 转发停止信号给 artex 本体。
#
# Docker 下这是必需的：docker stop 只把 SIGTERM 发给 PID 1（也就是本脚本），
# 不会发给子进程。不转发的话 artex 收不到信号、做不了优雅关闭，10 秒后被 SIGKILL
# 硬杀，正在跑的任务直接断在半路。
forward() {
	stopping=1
	if [ "$child" -ne 0 ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
	stop_empty_guard
}
trap forward INT TERM

start_empty_guard

delay=1
while :; do
	"$BIN" "$@" &
	child=$!

	# 信号会打断 wait 并让它返回 >128。此时子进程其实还在做优雅关闭，
	# 必须再 wait 一次才能拿到它真正的退出码。
	wait "$child"
	code=$?
	if [ "$code" -gt 128 ]; then
		wait "$child"
		code=$?
	fi
	child=0

	if [ "$stopping" -eq 1 ]; then
		stop_empty_guard
		echo "[artex] 已停止"
		exit 0
	fi

	case "$code" in
		0)
			stop_empty_guard
			echo "[artex] 正常退出"
			exit 0
			;;
		"$RESTART_CODE")
			# 更新/回滚已就绪：重跑后 artex 会在启动时完成换装（见 selfupdate.Bootstrap）。
			echo "[artex] 请求重启（应用新版本）…"
			delay=1
			;;
		*)
			echo "[artex] 异常退出 (code=$code)，${delay}s 后重启" >&2
			sleep "$delay"
			delay=$((delay * 2))
			[ "$delay" -gt "$MAX_DELAY" ] && delay=$MAX_DELAY
			;;
	esac
done
