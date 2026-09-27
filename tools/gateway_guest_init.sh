#!/bin/sh
# Disposable KVM lab PID 1. This file is not the production offline guest init.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mkdir -p /run
mountpoint -q /run || mount -t tmpfs tmpfs /run
modprobe virtio_net 2>/dev/null || true
modprobe nf_tables 2>/dev/null || true
modprobe nft_redir 2>/dev/null || true
python3 -u /opt/bull/gateway_guest_probe.py >/dev/console 2>&1 || true
printf '%s\n' 'BULL_GATEWAY_KVM_GUEST_DONE' >/dev/console
while :; do sleep 60; done
