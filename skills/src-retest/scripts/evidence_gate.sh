#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/evidence_gate.py" "${1:-}" "${2:-}"
