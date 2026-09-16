#!/usr/bin/env bash

set -euo pipefail

ROOTFS="$1"
PROJECT="$2"
PROJECT_MODE="$3"

shift 3


# =============================================================================
# PRIVATE MOUNT TREE
# =============================================================================

mount --make-rprivate /


# =============================================================================
# PRIVATE ROOT
# =============================================================================

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
    "$ROOTFS/workspace"


# =============================================================================
# HELPER — MIRROR SYSTEM RUNTIME PATH READ-ONLY
#
# Handles both directories and usr-merge symlinks such as:
#
#   /bin -> usr/bin
#   /lib -> usr/lib
#
# =============================================================================

mirror_runtime_path () {

    SRC="$1"
    NAME="$2"
    DST="$ROOTFS/$NAME"

    if [ -L "$SRC" ]; then

        TARGET="$(readlink "$SRC")"

        rm -rf "$DST"

        ln -s \
            "$TARGET" \
            "$DST"

        echo \
            "RUNTIME_SYMLINK_${NAME}=PASS"

        return 0

    fi


    if [ -d "$SRC" ]; then

        mkdir -p "$DST"

        mount \
            --rbind \
            "$SRC" \
            "$DST"

        # Do not propagate mount changes back toward the host.
        mount \
            --make-rslave \
            "$DST"

        # Top-level mount becomes read-only.
        mount \
            -o remount,bind,ro \
            "$DST"

        echo \
            "RUNTIME_RBIND_${NAME}=PASS"

        return 0

    fi


    if [ -f "$SRC" ]; then

        mkdir -p \
            "$(dirname "$DST")"

        touch "$DST"

        mount \
            --bind \
            "$SRC" \
            "$DST"

        mount \
            -o remount,bind,ro \
            "$DST"

        echo \
            "RUNTIME_FILE_${NAME}=PASS"

        return 0

    fi

}


# =============================================================================
# RUNTIME
# =============================================================================

mirror_runtime_path \
    /usr \
    usr

mirror_runtime_path \
    /bin \
    bin

mirror_runtime_path \
    /sbin \
    sbin

mirror_runtime_path \
    /lib \
    lib

mirror_runtime_path \
    /lib64 \
    lib64


# =============================================================================
# MINIMAL /etc
#
# Do not expose arbitrary host configuration.
# =============================================================================

for FILE in \
    passwd \
    group \
    nsswitch.conf \
    hosts \
    resolv.conf \
    localtime
do

    SRC="/etc/$FILE"
    DST="$ROOTFS/etc/$FILE"

    if [ -f "$SRC" ]; then

        mkdir -p \
            "$(dirname "$DST")"

        touch "$DST"

        mount \
            --bind \
            "$SRC" \
            "$DST"

        mount \
            -o remount,bind,ro \
            "$DST"

    fi

done


# =============================================================================
# MINIMAL DEVICES
# =============================================================================

for DEVICE in \
    null \
    zero \
    random \
    urandom
do

    SRC="/dev/$DEVICE"
    DST="$ROOTFS/dev/$DEVICE"

    if [ -e "$SRC" ]; then

        touch "$DST"

        mount \
            --bind \
            "$SRC" \
            "$DST"

    fi

done


# =============================================================================
# PRIVATE /tmp
# =============================================================================

mount \
    -t tmpfs \
    -o size=64m,nosuid,nodev \
    tmpfs \
    "$ROOTFS/tmp"

chmod \
    1777 \
    "$ROOTFS/tmp"


# =============================================================================
# PROJECT MOUNT
# =============================================================================

mount \
    --bind \
    "$PROJECT" \
    "$ROOTFS/workspace"

if [ "$PROJECT_MODE" = "ro" ]; then

    mount \
        -o remount,bind,ro \
        "$ROOTFS/workspace"

fi


# =============================================================================
# /proc intentionally omitted
#
# This host refuses a new procfs mount inside the namespace.
# PID isolation remains active through unshare --pid --fork.
# =============================================================================


# =============================================================================
# ENTER SANDBOX
#
# no_new_privs is set inside the sandbox immediately before workload exec.
# =============================================================================

exec \
    chroot \
    "$ROOTFS" \
    /usr/bin/python3.13 \
    -c '
import ctypes
import os
import sys

PR_SET_NO_NEW_PRIVS = 38

libc = ctypes.CDLL(
    None,
    use_errno=True,
)

result = libc.prctl(
    PR_SET_NO_NEW_PRIVS,
    1,
    0,
    0,
    0,
)

if result != 0:

    err = ctypes.get_errno()

    raise OSError(
        err,
        os.strerror(err),
    )


# ------------------------------------------------------------
# BULL-owned seccomp policy
# ------------------------------------------------------------

sys.path.insert(
    0,
    "/workspace/.bull_runtime"
)

from seccomp_policy import (
    install_bull_seccomp,
)

installed = install_bull_seccomp()

os.environ[
    "BULL_SECCOMP_ACTIVE"
] = "1"

os.environ[
    "BULL_SECCOMP_RULES"
] = ",".join(installed)


command = sys.argv[1:]

if not command:

    raise SystemExit(
        "missing sandbox command"
    )


os.execvp(
    command[0],
    command,
)
' \
    "$@"
