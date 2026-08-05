#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="strict"
if [[ "${1:-}" == "--readiness" ]]; then MODE="readiness"; shift; fi
if [[ $# -ne 4 ]]; then echo "usage: $0 [--readiness] APP DMG EXTENSION_ZIP RECEIPT" >&2; exit 2; fi
python3 "$ROOT/scripts/glassbox/verify_browser_artifact.py" "$MODE" "$ROOT" "$1" "$2" "$3" "$4"
