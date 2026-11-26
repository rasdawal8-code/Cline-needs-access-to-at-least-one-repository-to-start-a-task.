#!/usr/bin/env bash
# ============================================================
# GOTU Intelligence Platform — Start Script
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  source "$SCRIPT_DIR/.env"
  set +a
fi

# Build frontend if dist is missing or stale
FRONTEND_DIST="$SCRIPT_DIR/frontend/dist/index.html"
if [ ! -f "$FRONTEND_DIST" ]; then
  echo "[GOTU] Building frontend..."
  cd "$SCRIPT_DIR/frontend" && npm run build
  cd "$SCRIPT_DIR"
fi

echo "[GOTU] Starting server on ${HOST:-127.0.0.1}:${PORT:-4000}"
exec node "$SCRIPT_DIR/backend/src/server.js"
