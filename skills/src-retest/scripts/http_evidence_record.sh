#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/http_evidence.py" record \
  --outdir "${1:-}" \
  --name "${2:-}" \
  --method "${3:-GET}" \
  --url "${4:-}" \
  --header "${5:-}" \
  --cookie "${6:-}" \
  --bearer "${7:-}" \
  --body "${8:-}" \
  --content-type "${9:-}" \
  --max-redirs "${10:-0}" \
  --timeout "${11:-15}" \
  --expect-status "${12:-}" \
  --expect-contains "${13:-}" \
  --expect-not-contains "${14:-}" \
  --expect-content-type "${15:-}" \
  --expect-json-path "${16:-}" \
  --expect-json-value "${17:-}"
