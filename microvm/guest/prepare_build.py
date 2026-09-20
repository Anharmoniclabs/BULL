#!/usr/bin/env python3
"""Prepare an isolated Buildroot build from the pinned R3 inputs (no downloads)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PIN = 'd5180309b1b66ef3b8eaccca70ad69be8e0729a1'

def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--database-dir', type=Path, help='FreshClam-verified offline databases and detached signatures')
    args = parser.parse_args()
    os.umask(0o077)
    base = args.baseline.resolve(strict=True)
    dest = args.output.absolute()
    if dest.exists() or dest.is_relative_to(base):
        parser.error('output must be a new path outside the original build')
    source = base / 'sources/buildroot'
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != PIN or subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain']).strip():
        parser.error('Buildroot source must be the clean pinned revision')
    manifest = json.loads((base / 'evidence/guest-base-manifest.json').read_text())
    for name, expected in manifest['artifacts'].items():
        if sha(base / name) != expected:
            parser.error('baseline hash mismatch: ' + name)
    dest.mkdir(mode=0o700, parents=True)
    inputs = dest / 'inputs'
    inputs.mkdir()
    shutil.copytree(base / 'inputs/overlay', inputs / 'overlay')
    # Buildroot ClamAV uses /usr/share/clamav; keep the offline payload at the
    # conventional /var/lib/clamav location and provide the immutable alias.
    (inputs / 'overlay/usr/share').mkdir(parents=True, exist_ok=True)
    (inputs / 'overlay/usr/share/clamav').symlink_to('/var/lib/clamav')
    if args.database_dir:
        database = args.database_dir.resolve(strict=True)
        for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
            if not (database / name).is_file() or (database / name).is_symlink():
                parser.error('missing regular offline database: ' + name)
        target = inputs / 'overlay/var/lib/clamav'
        target.mkdir(parents=True, exist_ok=True)
        for path in database.iterdir():
            if path.is_file() and not path.is_symlink() and (path.suffix == '.cvd' or path.name.endswith('.cvd.sign')):
                shutil.copyfile(path, target / path.name)
    shutil.copyfile(Path(__file__).with_name('init'), inputs / 'overlay/sbin/bull-init')
    (inputs / 'overlay/sbin/bull-init').chmod(0o755)
    kernel = (base / 'inputs/linux.config').read_text()
    kernel = kernel.replace('CONFIG_IPV6_SIT=y', '# CONFIG_IPV6_SIT is not set')
    if '# CONFIG_IPV6_SIT is not set' not in kernel:
        kernel += '\n# CONFIG_IPV6_SIT is not set\n'
    (inputs / 'linux.config').write_text(kernel)
    config = (base / 'inputs/bull_defconfig').read_text().replace(str(base), str(dest))
    config = config.replace('BR2_LINUX_KERNEL_LATEST_VERSION=y',
        'BR2_LINUX_KERNEL_CUSTOM_VERSION=y\nBR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE="7.1.13"\nBR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_7_1=y')
    config = config.replace('BR2_TARGET_ROOTFS_EXT2_SIZE="512M"', 'BR2_TARGET_ROOTFS_EXT2_SIZE="1536M"')
    config += '\nBR2_TOOLCHAIN_BUILDROOT_CXX=y\n' + Path(__file__).with_name('production.fragment').read_text()
    (inputs / 'bull_defconfig').write_text(config)
    # Independent files, never hard links: download helpers can update their cache.
    shutil.copytree(base / 'downloads', dest / 'downloads')
    command = ['make', '-C', str(source), 'O=' + str(dest / 'output'),
               'BR2_DEFCONFIG=' + str(inputs / 'bull_defconfig'), 'defconfig']
    subprocess.run(command, check=True)
    record = {'buildroot_commit': revision, 'baseline': str(base), 'original_artifacts': manifest['artifacts'],
              'inputs': {str(p.relative_to(dest)): sha(p) for p in inputs.rglob('*') if p.is_file()},
              'symlinks': {str(p.relative_to(dest)): os.readlink(p) for p in inputs.rglob('*') if p.is_symlink()},
              'recipe_sha256': sha(Path(__file__)),
              'build_command': ['make', '-C', str(source), 'O=' + str(dest / 'output'), '-j2'],
              'status': 'PREPARED_NOT_BUILT'}
    (dest / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))

if __name__ == '__main__':
    main()
