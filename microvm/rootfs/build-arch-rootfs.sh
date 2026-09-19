#!/usr/bin/env bash
# Build a BULL guest tree from Arch packages, then seal it with build-ext4.sh.
set -euo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage: build-arch-rootfs.sh --output IMAGE [--tree TREE]

Requires pacstrap and sudo. The package manager installs into a private tree;
this never uses the host root as a guest source. Symlinks and hardlinks are
materialized before BULL's strict image builder admits the tree.
EOF
}
tree=
output=
while (($#)); do
    case "$1" in
        --tree) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; tree=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; output=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ -n $output ]] || { usage >&2; exit 2; }
command -v pacstrap >/dev/null || { echo 'pacstrap is required (install arch-install-scripts).' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required.' >&2; exit 1; }
[[ $EUID -ne 0 ]] || { echo 'Run as a normal user; the script uses sudo for pacstrap.' >&2; exit 1; }

assets=$(cd -- "$(dirname -- "$output")" && pwd -P)
output=$assets/$(basename -- "$output")
tree=${tree:-$assets/rootfs-tree}
[[ ! -e $output ]] || { echo "refusing to replace existing image: $output" >&2; exit 1; }
[[ ! -e $tree ]] || { echo "refusing to replace existing tree: $tree" >&2; exit 1; }
mkdir -p "$assets"
chmod 700 "$assets"
mkdir "$tree"
chmod 755 "$tree"

# Keep the package set explicit. Python is needed by the trusted adapter.
# Do not install systemd: its package hooks and host-runtime links are not
# needed by the small PID-1 shell supervisor and do not belong in this image.
sudo pacstrap -C /etc/pacman.conf -c -M "$tree" \
    bash coreutils filesystem glibc python util-linux procps-ng gawk grep sed

# Install the checked-out package before the root-owned tree is normalized.
# The production policy/integrity assets are deliberately not fabricated here.
package_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../src/bulldog" && pwd -P)
# Derive the guest's versioned site-packages directory from the tree instead
# of assuming the host or Arch repository's current Python minor version.
python_lib=$(find "$tree/usr/lib" -mindepth 1 -maxdepth 1 -type d -name 'python3.*' -print | sort -V | tail -n 1)
[[ -n $python_lib ]] || { echo 'guest Python site-packages directory not found.' >&2; exit 1; }
sudo mkdir -p "$python_lib/site-packages/bulldog"
sudo cp -a --no-preserve=ownership "$package_root/." "$python_lib/site-packages/bulldog/"
sudo chmod -R u=rwX,go=rX "$python_lib/site-packages/bulldog"

# These paths are mounted afresh by guest init. Remove package-manager or
# host-chroot pseudo-files before resolving links; never carry host /proc,
# /sys, /dev, /run, or temporary files into the image.
for mountpoint in dev proc sys run tmp; do
    sudo mkdir -p "$tree/$mountpoint"
    sudo find "$tree/$mountpoint" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
done

# The strict admitted-tree builder rejects links and hardlinks. Materialize
# both while preserving executable modes and refusing links outside the tree.
sudo python3 - "$tree" <<'PY'
from pathlib import Path
import os, shutil, stat, sys, tempfile

root = Path(sys.argv[1]).resolve(strict=True)
RUNTIME_ROOTS = {"dev", "proc", "sys", "run", "tmp"}

def is_runtime_path(path):
    relative = path.relative_to(root).parts
    return bool(relative) and (relative[0] in RUNTIME_ROOTS or relative[:2] in {("var", "run"), ("var", "lock")})

def walk_tree():
    # Never descend into guest mountpoints.  They are populated by PID 1 and
    # may be live pseudo-filesystems when this script is run via pacstrap.
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current)
        if is_runtime_path(current):
            dirs[:] = []
            files[:] = []
            continue
        dirs[:] = [name for name in dirs if not is_runtime_path(current / name)]
        yield current, dirs, files

def inside(path):
    try:
        path.relative_to(root)
    except ValueError:
        raise SystemExit(f"guest link escapes rootfs: {path}")

def runtime_link(path):
    relative = path.relative_to(root).parts
    if relative[:1] in {('dev',), ('proc',), ('sys',), ('run',), ('tmp',)}:
        return True
    if relative[:2] in {('var', 'run'), ('var', 'lock')}:
        return True
    try:
        target = os.readlink(path)
    except OSError:
        return False
    if target.startswith(('/dev/', '/proc/', '/sys/', '/run/', '/tmp/')):
        return True
    return target in {'/dev', '/proc', '/sys', '/run', '/tmp'}

for current, dirs, files in walk_tree():
    for name in list(dirs):
        path = current / name
        if not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=True)
        except FileNotFoundError:
            if runtime_link(path):
                path.unlink()
                continue
            raise
        inside(target)
        path.unlink()
        shutil.copytree(target, path, symlinks=False)
    for name in files:
        path = current / name
        if not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=True)
        except FileNotFoundError:
            if runtime_link(path):
                path.unlink()
                continue
            raise
        inside(target)
        mode = stat.S_IMODE(target.stat().st_mode)
        path.unlink()
        shutil.copy2(target, path)
        path.chmod(mode)

seen = {}
for current, dirs, files in walk_tree():
    for name in files:
        path = Path(current) / name
        info = path.stat()
        key = (info.st_dev, info.st_ino)
        if key not in seen:
            seen[key] = path
            continue
        mode = stat.S_IMODE(info.st_mode)
        with tempfile.NamedTemporaryFile(dir=current, delete=False) as stream:
            temporary = Path(stream.name)
            with path.open('rb') as source:
                shutil.copyfileobj(source, stream)
        temporary.chmod(mode)
        os.replace(temporary, path)

for current, dirs, files in walk_tree():
    for name in dirs + files:
        path = Path(current) / name
        if path.is_symlink():
            if runtime_link(path):
                path.unlink()
                continue
            raise SystemExit(f"unmaterialized guest link: {path}")
        if not path.resolve().is_relative_to(root):
            raise SystemExit(f"unmaterialized or escaping guest path: {path}")
PY

"$(dirname -- "${BASH_SOURCE[0]}")/build-ext4.sh" --source "$tree" --output "$output"
echo "Built guest rootfs: $output"
