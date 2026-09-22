#!/usr/bin/env bash

set -euo pipefail

ROOTFS="$1"
PROJECT="$2"
PROJECT_MODE="$3"
SANDBOX_PYTHON="$4"
RUNTIME_ROOT="$5"
shift 5

mount --make-rprivate /
mount -t tmpfs -o size=256m,nosuid,nodev tmpfs "$ROOTFS"

mkdir -p \
    "$ROOTFS/usr" "$ROOTFS/etc" "$ROOTFS/dev" "$ROOTFS/proc" \
    "$ROOTFS/tmp" "$ROOTFS/workspace" "$ROOTFS/bull_runtime"

mirror_runtime_path () {
    SRC="$1"
    NAME="$2"
    DST="$ROOTFS/$NAME"
    if [ -L "$SRC" ]; then
        TARGET="$(readlink "$SRC")"
        rm -rf "$DST"
        ln -s "$TARGET" "$DST"
        return 0
    fi
    if [ -d "$SRC" ]; then
        mkdir -p "$DST"
        mount --rbind "$SRC" "$DST"
        mount --make-rslave "$DST"
        mount -o remount,bind,ro "$DST"
        return 0
    fi
    if [ -f "$SRC" ]; then
        mkdir -p "$(dirname "$DST")"
        touch "$DST"
        mount --bind "$SRC" "$DST"
        mount -o remount,bind,ro "$DST"
    fi
}

mirror_runtime_path /usr usr
mirror_runtime_path /bin bin
mirror_runtime_path /sbin sbin
mirror_runtime_path /lib lib
mirror_runtime_path /lib64 lib64

for FILE in passwd group nsswitch.conf hosts resolv.conf localtime
do
    SRC="/etc/$FILE"
    DST="$ROOTFS/etc/$FILE"
    if [ -f "$SRC" ]; then
        mkdir -p "$(dirname "$DST")"
        touch "$DST"
        mount --bind "$SRC" "$DST"
        mount -o remount,bind,ro "$DST"
    fi
done

for DEVICE in null zero random urandom
do
    SRC="/dev/$DEVICE"
    DST="$ROOTFS/dev/$DEVICE"
    if [ -e "$SRC" ]; then
        touch "$DST"
        mount --bind "$SRC" "$DST"
    fi
done

mount -t tmpfs -o size=64m,nosuid,nodev,noexec tmpfs "$ROOTFS/tmp"
chmod 1777 "$ROOTFS/tmp"

mount --bind "$PROJECT" "$ROOTFS/workspace"
if [ "$PROJECT_MODE" = "ro" ]; then
    mount -o remount,bind,ro "$ROOTFS/workspace"
fi

mount --bind "$RUNTIME_ROOT" "$ROOTFS/bull_runtime"
mount -o remount,bind,ro "$ROOTFS/bull_runtime"

# /proc, /sys, host home, /run/user, Docker/container sockets and package caches
# are deliberately absent from the root filesystem.
export BULL_WORKSPACE_MODE="$PROJECT_MODE"

exec chroot "$ROOTFS" "$SANDBOX_PYTHON" -c '
import ctypes
import json
import os
import socket
import sys
import time

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
libc = ctypes.CDLL(None, use_errno=True)

if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err))

sys.path[:] = ["/bull_runtime"] + [
    entry for entry in sys.path
    if entry and not entry.startswith("/workspace")
]
from landlock_policy import LandlockUnavailable, install_bull_landlock
from seccomp_policy import install_bull_seccomp

profile = os.environ.get("BULL_SECCOMP_PROFILE", "compat").strip().lower()
workspace_writable = os.environ.get("BULL_WORKSPACE_MODE") == "rw"
landlock_active = False
landlock_abi = 0
try:
    landlock_abi = install_bull_landlock(workspace_writable=workspace_writable)
    landlock_active = True
except LandlockUnavailable:
    if profile == "strict":
        raise

# BULL-PENTEST-HARDENING: attest interfaces before seccomp
# if_nameindex() may use AF_NETLINK internally. Capture the namespace view
# before installing the narrower workload socket policy.
interfaces = sorted(name for _, name in socket.if_nameindex())
network_isolated = all(name == "lo" for name in interfaces)

installed = install_bull_seccomp(profile=profile)
os.environ["BULL_SECCOMP_ACTIVE"] = "1"
os.environ["BULL_SECCOMP_PROFILE"] = profile
os.environ["BULL_SECCOMP_RULES"] = ",".join(installed)

attest_fd_raw = os.environ.pop("BULL_ATTEST_FD", None)
attest_nonce = os.environ.pop("BULL_ATTEST_NONCE", None)
if attest_fd_raw is None or attest_nonce is None:
    raise SystemExit("missing trusted backend attestation channel")

attest_fd = int(attest_fd_raw)
no_new_privs = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
attestation = {
    "format": "bull-sandbox-attestation-v2",
    "nonce": attest_nonce,
    "pid": os.getpid(),
    "no_new_privs": no_new_privs,
    "seccomp": os.environ.get("BULL_SECCOMP_ACTIVE") == "1",
    "seccomp_profile": profile,
    "seccomp_rules": len(installed),
    "landlock": landlock_active,
    "landlock_abi": landlock_abi,
    "network_interfaces": interfaces,
    "network_isolated": network_isolated,
    "python": sys.executable,
    "runtime_root": "/bull_runtime",
    "bootstrap_complete_ns": time.monotonic_ns(),
}
os.write(attest_fd, (json.dumps(attestation, sort_keys=True) + "\n").encode("utf-8"))
os.close(attest_fd)

# BULL-ATTEST-PREEXEC-GATE-V1
go_fd_raw = os.environ.pop("BULL_GO_FD", None)
if go_fd_raw is None:
    raise SystemExit("missing trusted pre-exec release channel")
go_fd = int(go_fd_raw)
gate_token = os.read(go_fd, 1)
os.close(go_fd)
if gate_token != b"1":
    raise SystemExit("host did not release pre-exec attestation gate")

for key in (
    "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "BASH_ENV", "ENV", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
    "GIT_TEMPLATE_DIR", "GIT_EXEC_PATH", "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME", "SSH_AUTH_SOCK", "DOCKER_HOST",
):
    os.environ.pop(key, None)
os.environ["HOME"] = "/nonexistent"
os.environ["TMPDIR"] = "/tmp"
os.environ["PYTHONNOUSERSITE"] = "1"
os.environ["PYTHONSAFEPATH"] = "1"

command = sys.argv[1:]
if not command:
    raise SystemExit("missing sandbox command")
os.execvp(command[0], command)
' "$@"
