#!/bin/bash
# Data retention for ARTEX runtime artifacts.
# Config: /app/data/retention.env (persistent). Set RETENTION_DRY_RUN=1 to only
# report what would be deleted. Evidence, tasks and findings are NEVER touched.
set -u

DRY_ARG=0
[ "${1:-}" = "--dry-run" ] && DRY_ARG=1
CONF=/app/data/retention.env
[ -f "$CONF" ] && . "$CONF"

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

count_paths() {
  find "$1" -mindepth 1 -maxdepth 1 "$2" -mtime +"$3" 2>/dev/null | wc -l
}

SESS_N=$(count_paths /app/data/sessions -type d "$SESS_DAYS")
TRANS_N=$(count_paths /app/data/transcripts -type f "$TRANS_DAYS")
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
