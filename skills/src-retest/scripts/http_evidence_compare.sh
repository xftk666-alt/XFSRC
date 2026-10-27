#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/http_evidence.py" compare \
  --outdir "${1:-}" \
  --attack "${2:-}" \
  --control "${3:-}" \
  --attack-status "${4:-}" \
  --control-status "${5:-}" \
  --attack-contains "${6:-}" \
  --control-not-contains "${7:-}" \
  --bodies-differ "${8:-true}" \
  --json-path "${9:-}" \
  --attack-json-value "${10:-}"
