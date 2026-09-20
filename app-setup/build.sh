#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-${GRANTLINE_SRC:-reference}}"
SRC="$ROOT/$TARGET"
if [[ ! -d "$SRC" ]]; then
  echo "build: missing source directory $SRC" >&2
  exit 1
fi
if [[ -f "$SRC/package.json" ]]; then
  (cd "$SRC" && npm install --omit=dev 2>/dev/null || true)
fi
chmod +x "$SRC/bin/grantline.js" 2>/dev/null || true
echo "build: prepared $TARGET"
