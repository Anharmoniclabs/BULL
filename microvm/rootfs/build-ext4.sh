#!/usr/bin/env bash
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from bulldog.microvm_image import main; raise SystemExit(main())' "$SCRIPT_DIR/../../src" "$@"
