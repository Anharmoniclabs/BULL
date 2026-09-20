#!/usr/bin/env python3
"""Record a completed local guest build and verify original assets remain intact."""
import argparse
import json
from pathlib import Path
import subprocess

from prepare_build import sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve(strict=True)
    manifest = json.loads((root / 'manifest.json').read_text())
    baseline = Path(manifest['baseline'])
    for relative, expected in manifest['original_artifacts'].items():
        if sha(baseline / relative) != expected:
            parser.error('original asset changed: ' + relative)
    images = root / 'output/images'
    for name in ('bzImage', 'rootfs.ext4'):
        if not (images / name).is_file():
            parser.error('build output missing: ' + name)
    config = (root / 'output/build/linux-7.1.13/.config').read_text()
    if 'CONFIG_IPV6_SIT=y' in config or 'CONFIG_IPV6_SIT=m' in config:
        parser.error('unused SIT tunnel driver remains enabled')
    for option in ('USER_NS', 'PID_NS', 'NET_NS', 'SECCOMP_FILTER', 'SECURITY_LANDLOCK', 'VIRTIO_CONSOLE', 'CGROUP_PIDS', 'MEMCG'):
        if 'CONFIG_' + option + '=y' not in config:
            parser.error('mandatory guest kernel feature missing: ' + option)
    databases = root / 'inputs/overlay/var/lib/clamav'
    for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
        if not (databases / name).is_file():
            parser.error('offline database missing: ' + name)
    manifest['inputs'] = {str(p.relative_to(root)): sha(p) for p in (root / 'inputs').rglob('*') if p.is_file()}
    manifest['outputs'] = {str(p.relative_to(root)): sha(p) for p in (images / 'bzImage', images / 'rootfs.ext4', root / 'output/.config', root / 'output/build/linux-7.1.13/.config')}
    manifest['packages'] = subprocess.check_output(['make', '-s', '-C', str(baseline / 'sources/buildroot'),
                                                   'O=' + str(root / 'output'), 'show-info'], text=True)
    manifest['status'] = 'BUILT_GUEST_EXECUTION_NOT_YET_VALIDATED'
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(root / 'manifest.json')


if __name__ == '__main__':
    main()
