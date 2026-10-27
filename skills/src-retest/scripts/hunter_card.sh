#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/hunter_card.py" \
  --outdir "${1:-}" \
  --victim-marker "${2:-}" \
  --kind "${3:-}" \
  --attack "${4:-}" \
  --control "${5:-}" \
  --title "${6:-}" \
  --impact "${7:-}" \
  --claimed-severity "${8:-}" \
  --task-id "${9:-}"
