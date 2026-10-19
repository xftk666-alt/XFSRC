#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/retest_strict.py" signoff \
  --outdir "${1:-}" \
  --phrase "${2:-}" \
  --note "${3:-}"
