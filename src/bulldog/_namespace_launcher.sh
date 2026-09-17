#!/usr/bin/env bash

set -euo pipefail

ROOTFS="$1"
PROJECT="$2"
PROJECT_MODE="$3"
SANDBOX_PYTHON="$4"
RUNTIME_ROOT="$5"

shift 5

mount --make-rprivate /

mount \
    -t tmpfs \
    -o size=256m,nosuid,nodev \
    tmpfs \
    "$ROOTFS"

mkdir -p \
    "$ROOTFS/usr" \
    "$ROOTFS/etc" \
    "$ROOTFS/dev" \
    "$ROOTFS/proc" \
    "$ROOTFS/tmp" \
    "$ROOTFS/workspace" \
    "$ROOTFS/bull_runtime"

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
        return 0
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

mount -t tmpfs -o size=64m,nosuid,nodev tmpfs "$ROOTFS/tmp"
chmod 1777 "$ROOTFS/tmp"

mount --bind "$PROJECT" "$ROOTFS/workspace"
if [ "$PROJECT_MODE" = "ro" ]; then
    mount -o remount,bind,ro "$ROOTFS/workspace"
fi

# Security bootstrap code must never come from the agent-controlled project.
# Mount BULL's installed runtime package separately and read-only.
mount --bind "$RUNTIME_ROOT" "$ROOTFS/bull_runtime"
mount -o remount,bind,ro "$ROOTFS/bull_runtime"

# /proc is intentionally omitted. PID isolation is supplied by unshare --pid
# --fork, and the attestation below requires the bootstrap to observe PID 1.

exec \
    chroot \
    "$ROOTFS" \
    "$SANDBOX_PYTHON" \
    -c '
import ctypes
import json
import os
import socket
import sys

PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

libc = ctypes.CDLL(None, use_errno=True)

result = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
if result != 0:
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err))

# Import only the read-only BULL-owned security bootstrap. Drop every path
# inside the agent-controlled workspace, not merely one historical path.
sys.path[:] = ["/bull_runtime"] + [
    entry
    for entry in sys.path
    if entry and not entry.startswith("/workspace")
]
from seccomp_policy import install_bull_seccomp

profile = os.environ.get("BULL_SECCOMP_PROFILE", "compat").strip().lower()
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
interfaces = sorted(name for _, name in socket.if_nameindex())
network_isolated = all(name == "lo" for name in interfaces)

attestation = {
    "format": "bull-sandbox-attestation-v1",
    "nonce": attest_nonce,
    "pid": os.getpid(),
    "no_new_privs": no_new_privs,
    "seccomp": os.environ.get("BULL_SECCOMP_ACTIVE") == "1",
    "seccomp_profile": profile,
    "seccomp_rules": len(installed),
    "network_interfaces": interfaces,
    "network_isolated": network_isolated,
    "python": sys.executable,
    "runtime_root": "/bull_runtime",
}
os.write(
    attest_fd,
    (json.dumps(attestation, sort_keys=True) + "\n").encode("utf-8"),
)
os.close(attest_fd)

command = sys.argv[1:]
if not command:
    raise SystemExit("missing sandbox command")

os.execvp(command[0], command)
' \
    "$@"
