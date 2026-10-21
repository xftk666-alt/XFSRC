#!/bin/bash
# Data retention for ARTEX runtime artifacts.
# Config: /app/data/retention.env (persistent). Set RETENTION_DRY_RUN=1 to only
# report what would be deleted. Evidence, tasks and findings are NEVER touched.
set -u

DRY_ARG=0
[ "${1:-}" = "--dry-run" ] && DRY_ARG=1
CONF=/app/data/retention.env
# 配置来自 /app/data（agent 可写），绝不能 source 它：一行 `x=$(...)` 就是
# 以 root 身份执行的代码。只接受白名单里的 KEY=VALUE 数值。
if [ -f "$CONF" ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      RETENTION_ENABLED|RETENTION_SESSIONS_DAYS|RETENTION_TRANSCRIPTS_DAYS|\
      RETENTION_CHAT_ACTIVITY_DAYS|RETENTION_SERVER_LOG_DAYS|RETENTION_DRY_RUN)
        value="${value%\r}"
        value="${value#\"}"
        value="${value%\"}"
        case "$value" in
          *[!0-9]*|"") ;;   # 非数字一律忽略
          *) export "$key=$value" ;;
        esac
        ;;
    esac
  done < "$CONF"
fi

ENABLED="${RETENTION_ENABLED:-1}"
SESS_DAYS="${RETENTION_SESSIONS_DAYS:-30}"
TRANS_DAYS="${RETENTION_TRANSCRIPTS_DAYS:-30}"
CHAT_DAYS="${RETENTION_CHAT_ACTIVITY_DAYS:-90}"
LOG_DAYS="${RETENTION_SERVER_LOG_DAYS:-90}"
DRY="${RETENTION_DRY_RUN:-0}"
[ "$DRY_ARG" = "1" ] && DRY=1

if [ "$ENABLED" != "1" ]; then
  echo "[retention] disabled"
  exit 0
fi

STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[retention] $STAMP start (dry=$DRY sessions>${SESS_DAYS}d transcripts>${TRANS_DAYS}d chat>${CHAT_DAYS}d logs>${LOG_DAYS}d)"

# count_paths <dir> <d|f> <days>
# 旧签名把 "-type" 和 "d" 拆成两个参数，实际执行成 `-mtime +d`，find 报错后
# 被 2>/dev/null 吞掉、wc -l 恒为 0 —— 日志永远显示「没有候选」，但 rm 照样删。
count_paths() {
  [ -d "$1" ] || { echo 0; return; }
  find "$1" -mindepth 1 -maxdepth 1 -type "$2" -mtime +"$3" 2>/dev/null | wc -l | tr -d ' '
}

SESS_N=$(count_paths /app/data/sessions d "$SESS_DAYS")
TRANS_N=$(count_paths /app/data/transcripts f "$TRANS_DAYS")
echo "[retention] candidates: sessions=$SESS_N transcripts=$TRANS_N"

if [ "$DRY" != "1" ]; then
  find /app/data/sessions -mindepth 1 -maxdepth 1 -type d -mtime +"$SESS_DAYS" -exec rm -rf {} + 2>/dev/null
  find /app/data/transcripts -type f -mtime +"$TRANS_DAYS" -delete 2>/dev/null
fi

python3 - "$CHAT_DAYS" "$LOG_DAYS" "$DRY" <<'PY'
import os, sys
import psycopg2

chat_days, log_days, dry = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3] == "1"
dsn = os.environ.get("ARTEX_PG_DSN")
if not dsn:
    print("[retention] no ARTEX_PG_DSN; DB cleanup skipped")
    raise SystemExit(0)
try:
    conn = psycopg2.connect(dsn)
except Exception as exc:
    print("[retention] db connect failed: %s" % exc)
    raise SystemExit(0)

try:
    cur = conn.cursor()
    for table, days in (("conversation_activities", chat_days), ("server_logs", log_days)):
        cur.execute(
            "SELECT count(*) FROM %s WHERE created_at < now() - (%%s || ' days')::interval" % table,
            (days,),
        )
        n = cur.fetchone()[0]
        if dry:
            print("[retention] %s would delete %d rows" % (table, n))
            continue
        if n:
            cur.execute(
                "DELETE FROM %s WHERE created_at < now() - (%%s || ' days')::interval" % table,
                (days,),
            )
        print("[retention] %s deleted %d rows" % (table, cur.rowcount))
    if dry:
        conn.rollback()
    else:
        conn.commit()
except Exception as exc:
    conn.rollback()
    print("[retention] db cleanup failed: %s" % exc)
finally:
    conn.close()
PY

echo "[retention] $STAMP done"
