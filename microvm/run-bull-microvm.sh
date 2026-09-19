#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CONFIG_FILE="${BULL_MICROVM_CONFIG_FILE:-$SCRIPT_DIR/config/defaults.env}"

if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

: "${BULL_MICROVM_MEMORY_MIB:=512}"
: "${BULL_MICROVM_CPUS:=2}"
: "${BULL_MICROVM_ACCEL:=auto}"
: "${BULL_MICROVM_QEMU:=}"
: "${BULL_MICROVM_ENGINE_GUEST:=/bull_runtime/bin/bull-engine}"
: "${BULL_MICROVM_WORKSPACE:=}"
: "${BULL_MICROVM_RUNTIME_DIR:=$REPO_ROOT}"
: "${BULL_MICROVM_KERNEL:=}"
: "${BULL_MICROVM_ROOTFS:=}"

usage() {
    cat >&2 <<'USAGE'
Usage:
  run-bull-microvm.sh \
    --kernel PATH \
    --rootfs PATH \
    --workspace DIRECTORY \
    --bull-runtime DIRECTORY \
    [--engine /bull_runtime/relative/path] \
    [--memory-mib N] [--cpus N] [--qemu PATH] [--print-command]

PATH is a prebuilt guest Linux kernel. PATH for --rootfs may be an ext4 image
or a minimal rootfs directory; a directory is converted to a temporary ext4
image on Linux with microvm/rootfs/build-ext4.sh.

The engine path is guest-visible and must resolve below /bull_runtime. The
guest init passes it --workspace /workspace --runtime /bull_runtime and refuses
symlinks, workspace-provided commands, and paths outside the trusted runtime.

Examples:
  run-bull-microvm.sh \
    --kernel assets/vmlinux \
    --rootfs assets/rootfs.ext4 \
    --workspace /path/to/project \
    --bull-runtime /path/to/trusted/bull-runtime \
    --engine /bull_runtime/bin/bull-engine

  run-bull-microvm.sh --print-command \
    --kernel assets/vmlinux --rootfs assets/rootfs.ext4 \
    --workspace /path/to/project --bull-runtime /path/to/trusted/bull-runtime \
    --engine /bull_runtime/bin/bull-engine
USAGE
}

die() {
    printf 'run-bull-microvm.sh: %s\n' "$*" >&2
    exit 2
}

abs_dir() {
    [ -d "$1" ] || die "directory does not exist: $1"
    (cd -- "$1" && pwd -P)
}

abs_file() {
    [ -f "$1" ] || die "file does not exist: $1"
    dir="$(cd -- "$(dirname -- "$1")" && pwd -P)"
    printf '%s/%s\n' "$dir" "$(basename -- "$1")"
}

is_within() {
    case "$2/" in
        "$1/"*) return 0 ;;
        *) return 1 ;;
    esac
}

reject_qemu_delimiters() {
    case "$1" in
        *[[:space:],]*) die "QEMU path values may not contain whitespace or commas: $2" ;;
    esac
}

WORKSPACE="$BULL_MICROVM_WORKSPACE"
RUNTIME_DIR="$BULL_MICROVM_RUNTIME_DIR"
KERNEL="$BULL_MICROVM_KERNEL"
ROOTFS="$BULL_MICROVM_ROOTFS"
ENGINE_GUEST="$BULL_MICROVM_ENGINE_GUEST"
MEMORY_MIB="$BULL_MICROVM_MEMORY_MIB"
CPUS="$BULL_MICROVM_CPUS"
QEMU="$BULL_MICROVM_QEMU"
ACCEL="$BULL_MICROVM_ACCEL"
PRINT_COMMAND=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --workspace)
            [ "$#" -ge 2 ] || die "--workspace requires a directory"
            WORKSPACE=$2
            shift 2
            ;;
        --bull-runtime)
            [ "$#" -ge 2 ] || die "--bull-runtime requires a directory"
            RUNTIME_DIR=$2
            shift 2
            ;;
        --kernel)
            [ "$#" -ge 2 ] || die "--kernel requires a file"
            KERNEL=$2
            shift 2
            ;;
        --rootfs)
            [ "$#" -ge 2 ] || die "--rootfs requires an image or directory"
            ROOTFS=$2
            shift 2
            ;;
        --engine)
            [ "$#" -ge 2 ] || die "--engine requires a guest path"
            ENGINE_GUEST=$2
            shift 2
            ;;
        --memory-mib)
            [ "$#" -ge 2 ] || die "--memory-mib requires a number"
            MEMORY_MIB=$2
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || die "--cpus requires a number"
            CPUS=$2
            shift 2
            ;;
        --qemu)
            [ "$#" -ge 2 ] || die "--qemu requires a path"
            QEMU=$2
            shift 2
            ;;
        --accel)
            [ "$#" -ge 2 ] || die "--accel requires auto, kvm, or hvf"
            ACCEL=$2
            shift 2
            ;;
        --print-command)
            PRINT_COMMAND=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "unknown argument: $1"
            ;;
    esac
done

[ -n "$WORKSPACE" ] || die "--workspace is required"
[ -n "$RUNTIME_DIR" ] || die "--bull-runtime is required"
[ -n "$KERNEL" ] || die "--kernel is required"
[ -n "$ROOTFS" ] || die "--rootfs is required"

case "$MEMORY_MIB" in *[!0-9]*|'') die "--memory-mib must be a positive integer" ;; esac
case "$CPUS" in *[!0-9]*|''|0) die "--cpus must be a positive integer" ;; esac
[ "$MEMORY_MIB" -gt 0 ] || die "--memory-mib must be positive"

WORKSPACE="$(abs_dir "$WORKSPACE")"
RUNTIME_DIR="$(abs_dir "$RUNTIME_DIR")"
KERNEL="$(abs_file "$KERNEL")"
[ -e "$ROOTFS" ] || die "rootfs path does not exist: $ROOTFS"

if is_within "$WORKSPACE" "$RUNTIME_DIR" || is_within "$RUNTIME_DIR" "$WORKSPACE"; then
    die "workspace and bull runtime must be separate non-overlapping directories"
fi

case "$ENGINE_GUEST" in
    /bull_runtime/*) ;;
    *) die "--engine must be an absolute guest path below /bull_runtime" ;;
esac
reject_qemu_delimiters "$ENGINE_GUEST" engine
case "$ENGINE_GUEST" in
    */../*|*/..|*/./*|*/.|*//* )
        die "--engine must use a normalized path below /bull_runtime"
        ;;
esac
ENGINE_RELATIVE="${ENGINE_GUEST#/bull_runtime/}"
ENGINE_HOST="$RUNTIME_DIR/$ENGINE_RELATIVE"
[ -f "$ENGINE_HOST" ] || die "trusted engine is missing: $ENGINE_HOST"
[ -x "$ENGINE_HOST" ] || die "trusted engine is not executable: $ENGINE_HOST"
[ ! -L "$ENGINE_HOST" ] || die "trusted engine may not be a symlink: $ENGINE_HOST"

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bull-microvm.XXXXXX")"
cleanup() {
    rm -rf -- "$RUN_DIR"
}
trap cleanup EXIT

if [ -d "$ROOTFS" ]; then
    ROOTFS_IMAGE="$RUN_DIR/rootfs.ext4"
    "$SCRIPT_DIR/rootfs/build-ext4.sh" --source "$ROOTFS" --output "$ROOTFS_IMAGE"
else
    ROOTFS_IMAGE="$(abs_file "$ROOTFS")"
fi

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
case "$HOST_OS" in
    Linux)
        DEFAULT_ACCEL=kvm
        ;;
    Darwin)
        command -v sysctl >/dev/null 2>&1 || die "sysctl is required on macOS"
        DEFAULT_ACCEL=hvf
        ;;
    *)
        die "unsupported host OS: $HOST_OS; use Linux/KVM or macOS/HVF"
        ;;
esac

if [ "$ACCEL" = auto ]; then
    ACCEL="$DEFAULT_ACCEL"
fi
case "$ACCEL" in
    kvm)
        [ "$HOST_OS" = Linux ] || die "KVM is only valid on Linux"
        [ -r /dev/kvm ] && [ -w /dev/kvm ] \
            || die "KVM is unavailable; need read/write access to /dev/kvm"
        ;;
    hvf)
        [ "$HOST_OS" = Darwin ] || die "HVF is only valid on macOS"
        [ "$(sysctl -n kern.hv_support 2>/dev/null || printf '0')" = 1 ] \
            || die "Hypervisor.framework is unavailable (kern.hv_support != 1)"
        ;;
    *)
        die "unsupported accelerator: $ACCEL; refusing software emulation"
        ;;
esac

case "$HOST_ARCH" in
    x86_64|amd64)
        QEMU_DEFAULT=qemu-system-x86_64
        MACHINE=microvm,x-option-roms=off
        CONSOLE=ttyS0
        ;;
    arm64|aarch64)
        QEMU_DEFAULT=qemu-system-aarch64
        MACHINE=virt
        CONSOLE=ttyAMA0
        ;;
    *)
        die "unsupported host architecture: $HOST_ARCH"
        ;;
esac

if [ -z "$QEMU" ]; then
    QEMU="$QEMU_DEFAULT"
fi
if ! command -v "$QEMU" >/dev/null 2>&1 && [ ! -x "$QEMU" ]; then
    die "QEMU system emulator not found: $QEMU"
fi

if [ "$HOST_ARCH" = x86_64 ] || [ "$HOST_ARCH" = amd64 ]; then
    "$QEMU" -machine help 2>/dev/null | grep -Eq '(^|[[:space:]])microvm([[:space:]]|$)' \
        || die "installed QEMU lacks the microvm machine type"
fi

reject_qemu_delimiters "$WORKSPACE" workspace
reject_qemu_delimiters "$RUNTIME_DIR" bull-runtime
reject_qemu_delimiters "$ROOTFS_IMAGE" rootfs
reject_qemu_delimiters "$KERNEL" kernel

KERNEL_CMDLINE="console=$CONSOLE reboot=t panic=1 root=/dev/vda ro init=/sbin/bull-init bull.engine=$ENGINE_GUEST"

QEMU_ARGS=(
    "$QEMU"
    -M "$MACHINE"
    -accel "$ACCEL"
    -cpu host
    -m "${MEMORY_MIB}M"
    -smp "$CPUS"
    -nodefaults
    -no-user-config
    -nographic
    -display none
    -monitor none
    -no-reboot
    -kernel "$KERNEL"
    -append "$KERNEL_CMDLINE"
    -drive "id=rootfs,file=$ROOTFS_IMAGE,format=raw,if=none,readonly=on"
    -device virtio-blk-device,drive=rootfs
    -fsdev "local,id=bull_workspace,path=$WORKSPACE,security_model=none,readonly=on"
    -device virtio-9p-device,fsdev=bull_workspace,mount_tag=bull_workspace
    -fsdev "local,id=bull_runtime,path=$RUNTIME_DIR,security_model=none,readonly=on"
    -device virtio-9p-device,fsdev=bull_runtime,mount_tag=bull_runtime
    -net none
    -serial stdio
)

# QEMU's Linux seccomp sandbox further reduces the host-side QEMU attack
# surface. It is intentionally only enabled where QEMU implements it.
if [ "$HOST_OS" = Linux ]; then
    "$QEMU" -help 2>&1 | grep -q -- '-sandbox' \
        || die "QEMU lacks its host-side -sandbox option"
    QEMU_ARGS+=(
        -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
    )
fi

if [ "$PRINT_COMMAND" -eq 1 ]; then
    printf 'host=%s arch=%s accelerator=%s machine=%s\n' "$HOST_OS" "$HOST_ARCH" "$ACCEL" "$MACHINE"
    printf 'rootfs=%s\nworkspace=%s\nbull_runtime=%s\nengine=%s\n' \
        "$ROOTFS_IMAGE" "$WORKSPACE" "$RUNTIME_DIR" "$ENGINE_GUEST"
    printf 'command:'
    printf ' %q' "${QEMU_ARGS[@]}"
    printf '\n'
    exit 0
fi

exec "${QEMU_ARGS[@]}"
