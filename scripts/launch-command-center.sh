#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${PYTHONPATH:-}:$ROOT/src"
PORT="${BULL_COMMAND_CENTER_PORT:-8000}"
echo "Starting BULL Command Center on http://127.0.0.1:$PORT"
exec python ui/bull-command-center/dashboard_server.py --port "$PORT"
