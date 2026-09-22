#!/usr/bin/env bash
# Ubuntu CI helper. Keep FreshClam inside its packaged AppArmor paths, then
# export only signature-verified databases to a new private build directory.
set -euo pipefail
umask 077
if [ "$#" -ne 1 ] || [ "$(id -u)" -eq 0 ]; then
  echo 'Usage: bash tools/fetch_guest_databases.sh NEW_OUTPUT_DIRECTORY (normal user with sudo)' >&2
  exit 2
fi
destination="$1"
test -r /etc/clamav/freshclam.conf
mkdir -m 700 -- "$destination"
destination="$(cd -- "$destination" && pwd -P)"

# Avoid sharing the daemon's updater lock. No AppArmor policy is changed.
sudo -n systemctl stop clamav-freshclam.service
# This build uses offline clamscan, not a running clamd daemon.
sudo -n sed -i '/^NotifyClamd[[:space:]]/d' /etc/clamav/freshclam.conf
database="$(sudo -n mktemp -d /var/lib/clamav/bull-build.XXXXXXXX)"
sudo -n chown clamav:clamav "$database"
printf 'FreshClam configuration: /etc/clamav/freshclam.conf\nDatabase directory: %s\n' "$database"
/usr/bin/freshclam --version
sudo -n -u clamav /usr/bin/freshclam \
  --config-file=/etc/clamav/freshclam.conf --datadir="$database" --stdout

for name in main.cvd daily.cvd bytecode.cvd; do
  sudo -n test -f "$database/$name"
  sudo -n test ! -L "$database/$name"
  sudo -n install -m 600 -o "$(id -u)" -g "$(id -g)" \
    "$database/$name" "$destination/$name"
  sigtool --info="$destination/$name"
done
echo 'Official database download and CVD signature verification: PASS'
