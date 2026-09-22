#!/usr/bin/env bash
# Compatibility entry point for the portable init/configure/show workflow.
# No checkout reset, package installation, key rotation, or host changes.
set -euo pipefail
BULL_TOOL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec "${BULL_PYTHON:-python3}" "$BULL_TOOL_ROOT/tools/deployment_setup.py" "$@"
