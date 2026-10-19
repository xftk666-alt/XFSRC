#!/bin/bash
# interactsh OOB 管理器 —— 自建 OOB 服务器封装（稳定路径，勿放会话目录）
# 用法:
#   oobctl.sh gen          生成一个全新的专属 OOB 域名并启动后台会话
#   oobctl.sh log [logfile] 查看某会话捕获到的回连交互(默认最新会话)
#   oobctl.sh list         列出所有会话
#   oobctl.sh stop         停止所有 interactsh-client 会话
#
# 每个 gen 会话是独立的 correlation-id；同一轮测试请使用同一会话的域名。

# 配置来自持久卷；OOB_SERVER 为空表示禁用外部 OOB。
[ -f /app/data/oob/config.env ] && . /app/data/oob/config.env
SERVER="${OOB_SERVER:-}"
TOKEN="${OOB_TOKEN:-}"
if [ -z "$SERVER" ] || [ -z "$TOKEN" ]; then
  echo "OOB 未配置或已禁用（/app/data/oob/config.env）" >&2
  exit 2
fi
DIR="/app/data/oob"
mkdir -p "$DIR"

case "${1:-help}" in
  gen)
    for attempt in 1 2 3 4; do
      TS=$(date +%s%N)
      LOG="$DIR/session_$TS.log"
      nohup stdbuf -oL interactsh-client -s "$SERVER" -t "$TOKEN" -json -v > "$LOG" 2>&1 &
      echo $! > "$DIR/session_$TS.pid"
      DOMAIN=""
      for i in $(seq 1 45); do
        DOMAIN=$(grep -oE '[a-z0-9]{20,}\.oob\.aiboli\.top' "$LOG" 2>/dev/null | head -1)
        [ -n "$DOMAIN" ] && break
        if grep -q 'FTL' "$LOG" 2>/dev/null; then break; fi
        sleep 1
      done
      if [ -n "$DOMAIN" ]; then
        echo "OOB_DOMAIN=$DOMAIN"
        echo "OOB_LOG=$LOG"
        echo "OOB_SESSION=$TS"
        echo "提示: 用 $DOMAIN 作为 payload 目标；稍后用 'oobctl.sh log $LOG' 查看回连。"
        exit 0
      fi
      echo "[gen] 第 $attempt 次注册失败(瞬时超时)，5 秒后重试..." >&2
      kill "$(cat "$DIR/session_$TS.pid" 2>/dev/null)" 2>/dev/null || true
      sleep 5
    done
    echo "ERROR: 连续 4 次注册失败，请检查服务器/网络。最后一次日志："; tail -6 "$LOG"
    exit 1
    ;;
  log)
    LOG="${2:-$(ls -t "$DIR"/session_*.log 2>/dev/null | head -1)}"
    if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then echo "无会话日志"; exit 1; fi
    echo "== 会话日志: $LOG =="
    grep '"protocol"' "$LOG" 2>/dev/null || echo "(暂无回连交互)"
    ;;
  list)
    ls -lt "$DIR"/session_*.log 2>/dev/null || echo "(无会话)"
    ;;
  stop)
    if [ -n "${2:-}" ]; then
      PIDFILE="${2%.log}.pid"
      [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null && echo "已停止 $PIDFILE" && exit 0
    fi
    killed=0
    for pf in "$DIR"/session_*.pid; do
      [ -f "$pf" ] || continue
      kill "$(cat "$pf")" 2>/dev/null && killed=1
    done
    if [ "$killed" = 1 ]; then echo "已停止 oob 会话"; else echo "无运行中的会话"; fi
    ;;
  *)
    echo "用法: oobctl.sh {gen|log [logfile]|list|stop}"
    ;;
esac
