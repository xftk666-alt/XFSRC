#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/retest_strict.py" preview \
  --outdir "${1:-}" \
  --victim-marker "${2:-}" \
  --attack "${3:-}" \
  --control "${4:-}"
