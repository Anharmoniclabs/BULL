#!/bin/sh

# Install as /bull_runtime/bin/bull-engine, mode 0555. The guest rootfs must
# contain the installed BULL Python package. Guest PID 1 handles shutdown.
set -eu
exec /usr/bin/python3 -I -m bulldog.microvm_session "$@"
