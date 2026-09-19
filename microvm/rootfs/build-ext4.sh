#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

usage() {
    cat >&2 <<'USAGE'
Usage:
  build-ext4.sh --source ROOTFS_DIRECTORY --output ROOTFS_IMAGE [--replace]

The source directory must already contain a minimal Linux userspace with
/bin/sh, mount, sleep, and the guest kernel modules/filesystem support needed
by microvm/guest/init. The helper adds /sbin/bull-init and creates a raw ext4
image without requiring root. It is intended to run on Linux with e2fsprogs.
USAGE
}

die() {
    printf 'build-ext4.sh: %s\n' "$*" >&2
    exit 2
}

SOURCE_DIR=
OUTPUT=
REPLACE=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source)
            [ "$#" -ge 2 ] || die "--source requires a directory"
            SOURCE_DIR=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || die "--output requires a file"
            OUTPUT=$2
            shift 2
            ;;
        --replace)
            REPLACE=1
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

[ -n "$SOURCE_DIR" ] || { usage; die "--source is required"; }
[ -n "$OUTPUT" ] || { usage; die "--output is required"; }
[ -d "$SOURCE_DIR" ] || die "source is not a directory: $SOURCE_DIR"

for tool in du install mkfs.ext4 mktemp mv rm truncate; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

SOURCE_DIR="$(cd -- "$SOURCE_DIR" && pwd -P)"
OUTPUT_DIR="$(dirname -- "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"
OUTPUT="$OUTPUT_DIR/$(basename -- "$OUTPUT")"

if [ -e "$OUTPUT" ] && [ "$REPLACE" -ne 1 ]; then
    die "output exists; pass --replace to overwrite: $OUTPUT"
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/bull-rootfs.XXXXXX")"
IMAGE_TMP="$OUTPUT_DIR/.$(basename -- "$OUTPUT").$$.tmp"
cleanup() {
    rm -rf -- "$STAGE" "$IMAGE_TMP"
}
trap cleanup EXIT

cp -a "$SOURCE_DIR/." "$STAGE/"
install -d -m 0755 "$STAGE/sbin"
install -m 0755 "$SCRIPT_DIR/../guest/init" "$STAGE/sbin/bull-init"

source_kib="$(du -sk "$STAGE" | awk '{print $1}')"
image_kib=$((source_kib + 65536))
if [ "$image_kib" -lt 131072 ]; then
    image_kib=131072
fi

truncate -s "$((image_kib * 1024))" "$IMAGE_TMP"
mkfs.ext4 -q -F -L bull-rootfs -d "$STAGE" "$IMAGE_TMP"
chmod 0444 "$IMAGE_TMP"
mv -f -- "$IMAGE_TMP" "$OUTPUT"
trap - EXIT
rm -rf -- "$STAGE"
printf '%s\n' "$OUTPUT"
