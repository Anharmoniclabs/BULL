#!/usr/bin/env bash
# Isolated qualification; never changes main or removes unrelated containers.
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_OS_SRC="${BULL_OPENSHELL_SOURCE:-}"
TASK_OUTPUT=""
TASK_QUICK=0
TASK_PUSH=0
while (($#)); do
  case "$1" in
    --os-src|--output)
      if (($# < 2)) || [[ -z "$2" ]]; then echo "$1 requires a value" >&2; exit 2; fi
      if [[ "$1" == --os-src ]]; then TASK_OS_SRC="$2"; else TASK_OUTPUT="$2"; fi
      shift 2 ;;
    --quick) TASK_QUICK=1; shift ;;
    --push-results) TASK_PUSH=1; shift ;;
    --help)
      echo 'Usage: bash tools/run_codespace_openshell_operational.sh [--quick] [--os-src PATH] [--output NEW_PATH] [--push-results]'
      echo 'Full logs stay local; --push-results publishes compact reports to a new results branch.'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
command -v python3 >/dev/null || { echo 'Python 3.11+ is required' >&2; exit 2; }
if [[ -z "$TASK_OUTPUT" ]]; then
  TASK_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/bull-operational-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
else
  # Refuse reuse: old PASS reports must never stand in for a failed new run.
  if [[ -e "$TASK_OUTPUT" ]]; then echo "Output already exists; use a new path: $TASK_OUTPUT" >&2; exit 2; fi
  mkdir -p -- "$TASK_OUTPUT"
fi
TASK_OUTPUT="$(cd -- "$TASK_OUTPUT" && pwd)"
TASK_REPORTER="$TASK_ROOT/tools/openshell_qualification_results.py"
if [[ -n "$TASK_OS_SRC" ]]; then TASK_OS_SRC="$(realpath -m -- "$TASK_OS_SRC")"; fi
TASK_INIT_ARGS=()
if ((TASK_QUICK)); then TASK_INIT_ARGS=(--quick); fi
python3 "$TASK_REPORTER" init --root "$TASK_ROOT" --output "$TASK_OUTPUT" "${TASK_INIT_ARGS[@]}"

# Finalize and attempt an authorized evidence push, even after setup/test failure.
task_finish() {
  local task_original=$? task_report_rc task_push_rc=0
  trap - EXIT
  set +e
  python3 "$TASK_REPORTER" finalize --output "$TASK_OUTPUT" --runner-exit "$task_original" | tee -a "$TASK_OUTPUT/terminal.log"
  task_report_rc=${PIPESTATUS[0]}
  if ((TASK_PUSH)); then
    python3 "$TASK_REPORTER" publish --root "$TASK_ROOT" --output "$TASK_OUTPUT" 2>&1 | tee -a "$TASK_OUTPUT/terminal.log"
    task_push_rc=${PIPESTATUS[0]}
  fi
  printf 'Full terminal log: %s/terminal.log\nResults: %s/summary.json\n' "$TASK_OUTPUT" "$TASK_OUTPUT"
  if ((task_push_rc)); then exit 1; fi
  if ((task_original && task_report_rc == 0)); then exit "$task_original"; fi
  exit "$task_report_rc"
}
trap task_finish EXIT

# Separate phase logs and a complete terminal log. Heartbeats expose quiet jobs.
task_run() {
  local task_name="$1" task_rc task_worker task_heartbeat
  shift
  printf '\nRunning %s; log: %s/%s.log\n' "$task_name" "$TASK_OUTPUT" "$task_name" | tee -a "$TASK_OUTPUT/terminal.log"
  (
    set +e
    PYTHONUNBUFFERED=1 "$@" 2>&1 | tee "$TASK_OUTPUT/$task_name.log" | tee -a "$TASK_OUTPUT/terminal.log"
    task_pipeline=("${PIPESTATUS[@]}")
    if ((task_pipeline[0])); then exit "${task_pipeline[0]}"; fi
    if ((task_pipeline[1] || task_pipeline[2])); then exit 1; fi
    exit 0
  ) &
  task_worker=$!
  python3 - "$task_worker" "$task_name" "$TASK_OUTPUT" <<'PY' &
import os, sys, time
while True:
    time.sleep(15)
    try:
        os.kill(int(sys.argv[1]), 0)
    except ProcessLookupError:
        break
    print(f"  {sys.argv[2]} still running; live log: {sys.argv[3]}/{sys.argv[2]}.log", flush=True)
PY
  task_heartbeat=$!
  if wait "$task_worker"; then task_rc=0; else task_rc=$?; fi
  kill "$task_heartbeat" 2>/dev/null || true
  wait "$task_heartbeat" 2>/dev/null || true
  printf '%s\t%s\n' "$task_name" "$task_rc" >> "$TASK_OUTPUT/stage-exit-codes.tsv"
  return "$task_rc"
}

if ! task_run setup-venv python3 -m venv "$TASK_OUTPUT/venv"; then exit 1; fi
TASK_PYTHON="$TASK_OUTPUT/venv/bin/python"
if ! task_run setup-install "$TASK_PYTHON" -m pip install -e "$TASK_ROOT[test,mcp,openshell]"; then exit 1; fi
cd -- "$TASK_ROOT"
task_run regression "$TASK_PYTHON" -m pytest -q --junitxml="$TASK_OUTPUT/regression.xml" || true
TASK_SCALING=(--sizes 1000,10000,100000,1000000)
if ((TASK_QUICK)); then TASK_SCALING=(--skip-scaling); fi
task_run loopback "$TASK_PYTHON" tools/qualify_openshell_operational.py --output "$TASK_OUTPUT/loopback" --requests 10000 --workers 32 "${TASK_SCALING[@]}" || true

if [[ -z "$TASK_OS_SRC" ]]; then
  for path in /workspaces/{OpenShell,openshell} /workspaces/*/{OpenShell,openshell} /tmp/{OpenShell,openshell} /opt/{OpenShell,openshell}; do
    if [[ -f "$path/target/release/openshell" ]]; then TASK_OS_SRC="$path"; break; fi
  done
fi
if task_run native-preflight "$TASK_PYTHON" "$TASK_REPORTER" preflight --output "$TASK_OUTPUT" --os-src "$TASK_OS_SRC"; then
  task_run native_faults "$TASK_PYTHON" tools/qualify_openshell_native_faults.py --os-src "$TASK_OS_SRC" --output "$TASK_OUTPUT/native" || true
  task_run native_composition "$TASK_PYTHON" tools/openshell_experiment.py --os-src "$TASK_OS_SRC" --output "$TASK_OUTPUT/composition" --latency-n 100 || true
fi
