#!/bin/sh

# Copy this file to a trusted, executable path such as
# /bull_runtime/bin/bull-engine and replace the final exec with the real
# BULL-aware engine entrypoint used by your deployment.
set -eu

echo "No BULL engine adapter has been configured inside /bull_runtime/bin/bull-engine." >&2
exit 78
