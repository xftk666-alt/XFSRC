#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/http_evidence.py" summary --outdir "${1:-}"
