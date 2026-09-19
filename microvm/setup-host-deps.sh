#!/usr/bin/env bash
# Host prerequisites only: never reboot, log out, restart apps, or boot a guest.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: setup-host-deps.sh [--check | --non-interactive]

Without flags, install Linux x86-64 CachyOS/Arch dependencies with sudo and
enable KVM access if necessary. --check only inspects the current environment.
--non-interactive refuses password prompts and confirms the package transaction.
This does not build guest images or provision production policy/audit credentials.
EOF
}

mode=install
case "${1:-}" in
    '') ;;
    --check) mode=check ;;
    --non-interactive) mode=non-interactive ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { usage >&2; exit 2; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
    echo 'Only Linux x86-64/KVM is supported by this setup script.' >&2
    exit 1
}

check_host() {
    local missing=0 dependency
    for dependency in qemu-system-x86_64 mkfs.ext4 python3 mount pacstrap; do
        if command -v "$dependency" >/dev/null; then
            printf 'Available: %s\n' "$dependency"
        else
            printf 'Missing: %s\n' "$dependency" >&2
            missing=1
        fi
    done
    if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
        echo 'KVM device is accessible to this session.'
    else
        echo 'KVM device is missing or inaccessible to this session.' >&2
        missing=1
    fi
    if command -v qemu-system-x86_64 >/dev/null; then
        qemu-system-x86_64 --version
    fi
    echo 'This preflight is not a guest boot or production-readiness certification.'
    return "$missing"
}

if [[ $mode == check ]]; then
    check_host
    exit $?
fi

[[ $EUID -ne 0 ]] || {
    echo 'Run this script as your normal user; it invokes sudo only where needed.' >&2
    exit 1
}
# /etc/os-release is trusted operating-system metadata, not deployment input.
source /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *' arch '*|*' cachyos '*) ;;
    *) echo 'Automatic installation currently supports CachyOS/Arch only.' >&2; exit 1 ;;
esac

sudo_flags=()
pacman_flags=()
if [[ $mode == non-interactive ]]; then
    sudo_flags=(-n)
    pacman_flags=(--noconfirm)
fi
if ! command -v qemu-system-x86_64 >/dev/null || ! command -v mkfs.ext4 >/dev/null || ! command -v python3 >/dev/null || ! command -v mount >/dev/null || ! command -v pacstrap >/dev/null; then
    echo 'Installing QEMU, image tools, Python, util-linux and Arch guest bootstrap tools from configured repositories.'
    # Never refresh databases in isolation (-Sy) or silently upgrade the OS.
    # If repositories are stale, let pacman fail and resolve maintenance separately.
    sudo "${sudo_flags[@]}" pacman -S --needed "${pacman_flags[@]}" qemu-system-x86 e2fsprogs python util-linux arch-install-scripts
fi

if [[ ! -c /dev/kvm ]]; then
    if grep -qw svm /proc/cpuinfo; then
        module=kvm_amd
    elif grep -qw vmx /proc/cpuinfo; then
        module=kvm_intel
    else
        echo 'Hardware virtualization is not exposed; check firmware or nested-VM settings.' >&2
        exit 1
    fi
    sudo "${sudo_flags[@]}" modprobe "$module"
    [[ -c /dev/kvm ]] || {
        echo 'KVM module loaded but /dev/kvm is unavailable; check the host device configuration.' >&2
        exit 1
    }
fi

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    getent group kvm >/dev/null || {
        echo 'The operating system has no kvm group; repair host KVM configuration first.' >&2
        exit 1
    }
    [[ $(stat -c %G /dev/kvm) == kvm ]] || {
        echo '/dev/kvm is not assigned to the kvm group; inspect host udev configuration.' >&2
        exit 1
    }
    target_user=$(id -un)
    if [[ " $(id -nG "$target_user") " != *' kvm '* ]]; then
        sudo "${sudo_flags[@]}" usermod -a -G kvm "$target_user"
    fi
    echo 'KVM group membership takes effect in a new login session.'
    echo 'No session was restarted. Keep the active chat open; apply the login change later.'
fi

check_host
