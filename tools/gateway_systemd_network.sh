#!/bin/sh
# Disposable guest only. Bring up the single NIC after the drop rules are active.
set -eu
/usr/sbin/ip link set lo up
nic=
for path in /sys/class/net/*; do
    name=${path##*/}
    [ "$name" = lo ] && continue
    [ -z "$nic" ] || { echo 'expected exactly one guest NIC' >&2; exit 1; }
    nic=$name
done
[ -n "$nic" ] || { echo 'guest NIC missing' >&2; exit 1; }
/usr/sbin/ip link set "$nic" up
/usr/sbin/ip addr add 10.0.2.15/24 dev "$nic"
/usr/sbin/ip -6 addr add 2001:db8:42::1/64 dev "$nic"
