#!/usr/bin/env bash
set -euo pipefail
umask 077
# The Python launcher pins a private ./project_outputs export for this VM.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from bulldog.microvm import main; raise SystemExit(main())' "$SCRIPT_DIR/../src" "$@"
