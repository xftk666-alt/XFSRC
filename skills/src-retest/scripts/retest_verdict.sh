#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/retest_strict.py" verdict \
  --outdir "${1:-}" \
  --verdict "${2:-}" \
  --submit-advice "${3:-}" \
  --summary "${4:-}" \
  --victim-marker "${5:-}" \
  --kind "${6:-}" \
  --attack "${7:-}" \
  --control "${8:-}"
