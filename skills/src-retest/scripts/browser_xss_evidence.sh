#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export NODE_PATH="${NODE_PATH:-/usr/lib/node_modules}"
exec node "$DIR/browser_xss_evidence.js" \
  --outdir "${1:-}" \
  --name "${2:-xss}" \
  --url "${3:-}" \
  --selector "${4:-#searchValue}" \
  --wait-ms "${5:-4000}"
