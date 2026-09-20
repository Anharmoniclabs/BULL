#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO_URL="${BULL_REPO_URL:-https://github.com/Anharmoniclabs/BULL.git}"
BRANCH="${BULL_BRANCH:-main}"
BASE="${BULL_PRODUCTION_HOME:-$HOME/.local/share/bull-production}"
REPO_DIR="${BULL_REPO_DIR:-$BASE/BULL}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/bull"
ENV_FILE="$CONFIG_DIR/production.env"
SECRET_DIR="$BASE/secrets"
STATE_DIR="$BASE/state"
SNAPSHOT_DIR="$STATE_DIR/snapshots"
AUDIT_DIR="$STATE_DIR/audit"
REPORT_DIR="$STATE_DIR/reports"
MANIFEST="$STATE_DIR/integrity.json"
POLICY="$STATE_DIR/policy.json"
AUDIT_LEDGER="$AUDIT_DIR/audit.jsonl"
ANCHOR_URL="${BULL_REMOTE_AUDIT_ANCHOR_URL:-}"
ANCHOR_KEY_FILE="${BULL_REMOTE_AUDIT_ANCHOR_KEY_FILE:-}"
PROJECT_ROOT="${BULL_POLICY_PROJECT_ROOT:-/workspace}"
CAPS="${BULL_PRODUCTION_CAPABILITIES:-fs.read.project,process.exec}"
CGROUP_PARENT="${BULL_CGROUP_PARENT:-/sys/fs/cgroup/bull-$UID}"

usage() {
  cat <<EOF
BULL production host provisioner

Required:
  --anchor-url HTTPS_URL
  --anchor-key-file PATH

Optional:
  --project-root PATH
  --capabilities CSV
  --cgroup-parent PATH
  --repo-dir PATH
  --help

This provisions the laptop-side production boundary and verifies it.
Localhost/test audit anchors are deliberately rejected by BULL production mode.
EOF
}

while (($#)); do
  case "$1" in
    --anchor-url) ANCHOR_URL="$2"; shift 2 ;;
    --anchor-key-file) ANCHOR_KEY_FILE="$2"; shift 2 ;;
    --project-root) PROJECT_ROOT="$2"; shift 2 ;;
    --capabilities) CAPS="$2"; shift 2 ;;
    --cgroup-parent) CGROUP_PARENT="$2"; shift 2 ;;
    --repo-dir) REPO_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
say() { printf '\n=== %s ===\n' "$*"; }

[[ "$(uname -s)" == Linux ]] || die "production provisioning currently targets Linux"
[[ "$(uname -m)" == x86_64 ]] || die "current validated production target is Linux x86-64"
for c in git python3 openssl unshare sha256sum; do need "$c"; done

[[ -n "$ANCHOR_URL" ]] || die "--anchor-url is required"
python3 - "$ANCHOR_URL" <<'PY'
import sys
from urllib.parse import urlsplit
u=urlsplit(sys.argv[1])
if u.scheme != "https" or not u.hostname:
    raise SystemExit("audit anchor must be an absolute HTTPS URL")
if u.hostname in {"localhost","127.0.0.1","::1"}:
    raise SystemExit("localhost cannot satisfy BULL production audit readiness")
if u.username or u.password or u.fragment:
    raise SystemExit("audit anchor URL may not contain credentials or a fragment")
PY

[[ -n "$ANCHOR_KEY_FILE" ]] || die "--anchor-key-file is required"
[[ -f "$ANCHOR_KEY_FILE" ]] || die "anchor key file does not exist: $ANCHOR_KEY_FILE"
[[ ! -L "$ANCHOR_KEY_FILE" ]] || die "anchor key file must not be a symlink"
chmod 600 "$ANCHOR_KEY_FILE"
ANCHOR_KEY_FILE="$(readlink -f "$ANCHOR_KEY_FILE")"
(( $(wc -c < "$ANCHOR_KEY_FILE") >= 32 )) || die "anchor key must contain at least 32 bytes"

say "SOURCE"
mkdir -p "$BASE"
if [[ ! -d "$REPO_DIR/.git" ]]; then git clone "$REPO_URL" "$REPO_DIR"; fi
git -C "$REPO_DIR" fetch --prune origin
git -C "$REPO_DIR" checkout "$BRANCH"
git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
git -C "$REPO_DIR" status --porcelain | grep -q . && die "repository is not clean"
COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD)"
echo "commit: $COMMIT"

say "INSTALL"
if [[ ! -d "$BASE/venv" ]]; then python3 -m venv "$BASE/venv"; fi
"$BASE/venv/bin/python" -m pip install --upgrade pip
"$BASE/venv/bin/python" -m pip install -e "$REPO_DIR" pytest
BULL="$BASE/venv/bin/bull"

say "PRIVATE STATE"
install -d -m 700 "$CONFIG_DIR" "$SECRET_DIR" "$STATE_DIR" "$SNAPSHOT_DIR" "$AUDIT_DIR" "$REPORT_DIR"
INTEGRITY_KEY_FILE="$SECRET_DIR/integrity.key"
POLICY_KEY_FILE="$SECRET_DIR/policy.key"
[[ -f "$INTEGRITY_KEY_FILE" ]] || openssl rand -hex 32 > "$INTEGRITY_KEY_FILE"
[[ -f "$POLICY_KEY_FILE" ]] || openssl rand -hex 32 > "$POLICY_KEY_FILE"
chmod 600 "$INTEGRITY_KEY_FILE" "$POLICY_KEY_FILE"

say "DELEGATED CGROUP V2"
[[ -e /sys/fs/cgroup/cgroup.controllers ]] || die "cgroup v2 is unavailable"
if [[ ! -d "$CGROUP_PARENT" || ! -w "$CGROUP_PARENT" ]]; then
  command -v sudo >/dev/null 2>&1 || die "sudo is required to create delegated cgroup parent"
  sudo sh -c 'for x in cpu memory pids; do grep -qw "$x" /sys/fs/cgroup/cgroup.controllers && echo "+$x" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true; done'
  sudo mkdir -p "$CGROUP_PARENT"
  sudo chown "$UID:$(id -g)" "$CGROUP_PARENT"
fi
[[ -w "$CGROUP_PARENT" && -x "$CGROUP_PARENT" ]] || die "cgroup parent is not writable: $CGROUP_PARENT"
[[ -e "$CGROUP_PARENT/cgroup.procs" ]] || die "cgroup parent lacks cgroup.procs: $CGROUP_PARENT"
TEST_CG="$CGROUP_PARENT/.bull-provision-test-$$"
mkdir "$TEST_CG" || die "cannot create delegated cgroup child"
for f in memory.max pids.max cpu.max cgroup.procs; do
  [[ -e "$TEST_CG/$f" ]] || { rmdir "$TEST_CG" 2>/dev/null || true; die "delegated cgroup child lacks $f"; }
done
rmdir "$TEST_CG"

say "SIGNED POLICY + INTEGRITY"
export BULL_INTEGRITY_MANIFEST_KEY="$(cat "$INTEGRITY_KEY_FILE")"
export BULL_POLICY_BUNDLE_KEY="$(cat "$POLICY_KEY_FILE")"
"$BULL" manifest --output "$MANIFEST" --key-id "production-$USER"
POLICY_ARGS=(policy --output "$POLICY" --project-root "$PROJECT_ROOT" --key-id "production-policy-$USER")
IFS=',' read -r -a CAP_ARRAY <<< "$CAPS"
for cap in "${CAP_ARRAY[@]}"; do
  cap="${cap//[[:space:]]/}"
  [[ -n "$cap" ]] && POLICY_ARGS+=(--capability "$cap")
done
"$BULL" "${POLICY_ARGS[@]}"

say "PRODUCTION ENVIRONMENT"
SESSION_ID="$(openssl rand -hex 32)"
cat > "$ENV_FILE" <<EOF
# Generated for BULL source commit $COMMIT. Owner-only; never commit.
export BULL_SECCOMP_PROFILE=strict
export BULL_INTEGRITY_MANIFEST='$MANIFEST'
export BULL_INTEGRITY_MANIFEST_KEY="\$(cat '$INTEGRITY_KEY_FILE')"
export BULL_POLICY_BUNDLE='$POLICY'
export BULL_POLICY_BUNDLE_KEY="\$(cat '$POLICY_KEY_FILE')"
export BULL_SNAPSHOT_ROOT='$SNAPSHOT_DIR'
export BULL_AUDIT_LEDGER='$AUDIT_LEDGER'
export BULL_CGROUP_PARENT='$CGROUP_PARENT'
export BULL_AUDIT_TRANSPORT=https
export BULL_REMOTE_AUDIT_ANCHOR_URL='$ANCHOR_URL'
export BULL_REMOTE_AUDIT_ANCHOR_KEY="\$(cat '$ANCHOR_KEY_FILE')"
export BULL_AUDIT_SESSION_ID='$SESSION_ID'
EOF
chmod 600 "$ENV_FILE"
source "$ENV_FILE"

say "PRODUCTION GATE"
REPORT="$REPORT_DIR/production-$(date -u +%Y%m%dT%H%M%SZ).json"
"$BULL" verify --production --json "$REPORT"

say "REMOTE ANCHOR ACKNOWLEDGEMENT"
"$BASE/venv/bin/python" - <<'PY'
import os
from pathlib import Path
from bulldog.audit import AuditLedger
from bulldog.audit_transport import production_transport_from_environment
ledger = AuditLedger(Path(os.environ["BULL_AUDIT_LEDGER"]), transport=production_transport_from_environment())
before = ledger.verify()
if not before.valid:
    raise SystemExit("local audit ledger is invalid before probe")
ledger.append_event("production_provision_probe", {"purpose": "remote-anchor-readiness"})
after = ledger.verify()
if not after.valid or after.records < before.records + 1:
    raise SystemExit("audit probe did not commit correctly")
print("authenticated remote audit acknowledgement: PASS")
print("ledger records:", after.records)
print("head:", after.head_hash)
PY

say "PRODUCTION RUNTIME CONSTRUCTION"
"$BASE/venv/bin/python" - <<'PY'
from bulldog.profiles import ProductionRuntime, ProductionDispatcher
runtime = ProductionRuntime()
dispatcher = ProductionDispatcher(runtime=runtime)
assert runtime.production_boundary is True
assert dispatcher.production_mode is True
print("ProductionRuntime: PASS")
print("ProductionDispatcher: PASS")
PY

say "FINAL"
echo "BULL production provisioning: PASS"
echo "source commit: $COMMIT"
echo "environment: $ENV_FILE"
echo "verification report: $REPORT"
echo "audit ledger: $AUDIT_LEDGER"
echo
echo "Load in a new shell:"
echo "  source '$ENV_FILE'"
echo "Re-check:"
echo "  '$BULL' verify --production"
