#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$ROOT/.build" "$ROOT/submission" "$ROOT/agent-output"
find "$ROOT" -name 'store.json' -path '*/tmp/*' -delete 2>/dev/null || true
echo "reset: clean"
