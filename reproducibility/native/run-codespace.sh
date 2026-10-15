#!/usr/bin/env bash
# Build and run the archived native experiment, preserving failures for review.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
parent=${BULL_RUN_PARENT:-/workspaces}
run_dir=$(mktemp -d "$parent/bull-native-XXXXXXXX")
export BULL_NATIVE_RUN_DIR="$run_dir"
finish() {
  status=$?
  trap - EXIT
  python3 - "$run_dir" "$status" <<'PY'
import hashlib, json, pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
code = int(sys.argv[2])
(root / 'launcher-status.json').write_text(json.dumps({
    'exit_code': code,
    'meaning': 'Read results/report.json for native test status; launcher success alone is not evidence.'
}, indent=2) + '\n')
# Export logs and observations, excluding generated private keys, databases,
# policy bundles and authorization state. Full originals remain in run_dir.
allowed = {'report.json', 'results.json', 'provenance.json', 'native-preflight.json',
           'build-report.json', 'launcher-status.json', 'correlation.json',
           'upstream-receipts-A.json', 'upstream-receipts-B.json', 'latency-raw.json'}
files = []
for p in sorted(root.rglob('*')):
    if not p.is_file() or p.is_symlink() or 'BULL-Native-Reproduction' in p.parts or 'OpenShell' in p.parts:
        continue
    if p.name in allowed or p.suffix in {'.log', '.jsonl', '.csv'} or p.name.startswith('ocsf-'):
        files.append(p)
manifest = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root)}\n' for p in files)
archive = root / 'results-to-review.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in files:
        z.write(p, str(p.relative_to(root)))
    z.writestr('SHA256SUMS', manifest)
print('\nResults to review:', archive)
print('Original runtime files:', root)
print('Launcher exit code:', code)
PY
  exit "$status"
}
trap finish EXIT
printf '%s\n' 'd90b3b37610d01a119299965bcae3d5c564617782c7cef16402d43c313ca6492  BULL-Native-Reproduction.zip' |
  (cd "$here" && sha256sum -c -)
python3 - "$here/BULL-Native-Reproduction.zip" "$run_dir" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2])
PY
cd "$run_dir/BULL-Native-Reproduction"
sha256sum --quiet -c SOURCE_SHA256SUMS
# The bundled wheels require this exact Python minor version.
python3.12 --version 2>&1 | tee "$run_dir/python-version.log"
docker info 2>&1 | tee "$run_dir/docker-info.log"
python3 tools/prepare_codespace_openshell.py \
  --source "$run_dir/OpenShell" \
  --report "$run_dir/build-report.json" --jobs 2 \
  2>&1 | tee "$run_dir/build.log"
bash examples/saf_native/run.sh "$run_dir/OpenShell" "$run_dir/results" \
  2>&1 | tee "$run_dir/run.log"
