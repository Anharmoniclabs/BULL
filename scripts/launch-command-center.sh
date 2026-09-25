#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="${PYTHONPATH:-}:$ROOT/src"
PORT="${BULL_COMMAND_CENTER_PORT:-11510}"
HOST="${BULL_COMMAND_CENTER_HOST:-}"
ARGS=(up --workspace "$ROOT" --port "$PORT" --no-open-browser)
if [[ -n "$HOST" ]]; then ARGS+=(--host "$HOST"); fi
exec bull "${ARGS[@]}"
