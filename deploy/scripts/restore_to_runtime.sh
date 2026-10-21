#!/bin/bash
# Restore the whole hardened runtime tree onto /usr/local/share/artex-src.
# /app/skills and /app/data are bind-mounted (persistent); /usr/local/share is
# part of the container writable layer and disappears when the container is
# recreated. Keep this script idempotent and cheap.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"   # /app/skills/src-retest/scripts
SKILL="$(cd "$SRC/.." && pwd)"         # /app/skills/src-retest
DST=/usr/local/share/artex-src
DATA=/app/data/evidence
mkdir -p "$DST" "$DATA"
chmod 700 "$DATA" 2>/dev/null || true

# 1) Full runtime snapshot (scripts, srctools, helper modules).
if [ -d "$SKILL/runtime" ]; then
  cp -a "$SKILL/runtime/." "$DST/"
fi

# 2) Explicit critical list (kept as a fallback for older snapshots).
for f in retest_strict.py evidence_seal.py hunter_card.py submit_brief.py http_evidence.py evidence_gate.py \
         lab_detect.py scope_check.py coverage_record.py coverage_report.py dup_check.py report_check.py \
         test_retest_adversarial.py test_gates_hardening.py \
         retest_strict_gate.sh retest_verdict.sh retest_signoff.sh retest_preview.sh hunter_card.sh \
         http_evidence_record.sh http_evidence_compare.sh http_evidence_summary.sh evidence_gate.sh \
         browser_xss_evidence.js browser_xss_evidence.sh; do
  if [ -f "$SRC/$f" ]; then
    cp -f "$SRC/$f" "$DST/$f"
  fi
done

# 3) HMAC key / recorder token live in the runtime tree ONLY.
#
# They used to be mirrored into /app/data/evidence as well. /app/data is the
# agent's working directory — reachable by its Bash and by the workspace file
# manager — so a copy there put the evidence signing key within arm's reach of
# the code it is supposed to constrain. Seed the runtime copy from any existing
# data-dir copy once (migration), then delete the data-dir copy.
if [ -f "$DATA/.hmac-key" ] && [ ! -f "$DST/.evidence-hmac-key" ]; then
  cp -f "$DATA/.hmac-key" "$DST/.evidence-hmac-key"
fi
if [ -f "$DATA/.recorder-token" ] && [ ! -f "$DST/.recorder-token" ]; then
  cp -f "$DATA/.recorder-token" "$DST/.recorder-token"
fi
rm -f "$DATA/.hmac-key" "$DATA/.recorder-token" 2>/dev/null || true
chmod 400 "$DST/.evidence-hmac-key" "$DST/.recorder-token" 2>/dev/null || true
chmod +x "$DST"/*.sh "$DST"/*.py "$DST"/srctools/*.sh 2>/dev/null || true

# 4) Hide the evidence directory from the HTTP workspace browser by removing
#    nothing — the server now denies these subtrees itself. Just log the state.
echo "[src-retest] restored runtime snapshot to $DST ($(find "$DST" -maxdepth 1 | wc -l) entries)"
