#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/retest_strict.py" gate \
  --outdir "${1:-}" \
  --kind "${2:-}" \
  --victim-marker "${3:-}" \
  --attack "${4:-}" \
  --control "${5:-}"
