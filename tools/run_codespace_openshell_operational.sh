#!/usr/bin/env bash
# Isolated qualification; never changes main or removes unrelated containers.
set -euo pipefail
TASK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TASK_OS_SRC="${BULL_OPENSHELL_SOURCE:-}"
TASK_OUTPUT=""
TASK_QUICK=0
while (($#)); do
  case "$1" in
    --os-src) TASK_OS_SRC="$2"; shift 2 ;;
    --output) TASK_OUTPUT="$2"; shift 2 ;;
    --quick) TASK_QUICK=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$TASK_OUTPUT" ]]; then TASK_OUTPUT="$(mktemp -d /tmp/bull-operational-20260930-XXXXXX)"; fi
mkdir -p -- "$TASK_OUTPUT"
TASK_OUTPUT="$(cd -- "$TASK_OUTPUT" && pwd)"
if [[ -z "$TASK_OS_SRC" ]]; then
  for path in /workspaces/OpenShell /workspaces/openshell /tmp/OpenShell /tmp/openshell /opt/OpenShell /opt/openshell; do
    if [[ -f "$path/target/release/openshell" ]]; then TASK_OS_SRC="$path"; break; fi
  done
fi
python3 -m venv "$TASK_OUTPUT/venv"
TASK_PYTHON="$TASK_OUTPUT/venv/bin/python"
"$TASK_PYTHON" -m pip install -e "$TASK_ROOT[test,mcp,openshell]" > "$TASK_OUTPUT/install.log" 2>&1
cd -- "$TASK_ROOT"
set +e
"$TASK_PYTHON" -m pytest -q --junitxml="$TASK_OUTPUT/regression.xml" > "$TASK_OUTPUT/regression.log" 2>&1
TASK_REGRESSION=$?
tail -n 5 "$TASK_OUTPUT/regression.log"
TASK_SCALING=(--sizes 1000,10000,100000,1000000)
if ((TASK_QUICK)); then TASK_SCALING=(--skip-scaling); fi
"$TASK_PYTHON" tools/qualify_openshell_operational.py --output "$TASK_OUTPUT/loopback" --requests 10000 --workers 32 "${TASK_SCALING[@]}" > "$TASK_OUTPUT/loopback.log" 2>&1
TASK_LOOPBACK=$?
TASK_NATIVE=2
TASK_COMPOSITION=2
if [[ -n "$TASK_OS_SRC" ]]; then
  "$TASK_PYTHON" tools/qualify_openshell_native_faults.py --os-src "$TASK_OS_SRC" --output "$TASK_OUTPUT/native" > "$TASK_OUTPUT/native.log" 2>&1
  TASK_NATIVE=$?
  if ((TASK_NATIVE != 2)); then
    "$TASK_PYTHON" tools/openshell_experiment.py --os-src "$TASK_OS_SRC" --output "$TASK_OUTPUT/composition" --latency-n 100 > "$TASK_OUTPUT/composition.log" 2>&1
    TASK_COMPOSITION=$?
  fi
else
  echo 'Native tests BLOCKED: provide --os-src /path/to/built/pinned/OpenShell' | tee "$TASK_OUTPUT/native.log"
fi
set -e
"$TASK_PYTHON" - "$TASK_OUTPUT" "$TASK_REGRESSION" "$TASK_LOOPBACK" "$TASK_NATIVE" "$TASK_COMPOSITION" <<'PY'
import json, pathlib, sys, subprocess
out=pathlib.Path(sys.argv[1]); statuses=dict(zip(('regression','loopback','native_faults','native_composition'),map(int,sys.argv[2:])))
report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(), 'exit_codes':statuses,
        'native_identity_export':'OPEN; shorthand correlation is still heuristic',
        'output':str(out)}
(out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
PY
printf 'Evidence: %s\n' "$TASK_OUTPUT/summary.json"
if ((TASK_REGRESSION || TASK_LOOPBACK)); then exit 1; fi
if ((TASK_NATIVE == 2 || TASK_COMPOSITION == 2)); then exit 2; fi
if ((TASK_NATIVE || TASK_COMPOSITION)); then exit 1; fi
