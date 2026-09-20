#!/usr/bin/env python3
"""Apply the recipe's database alias to a new image without altering its input."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from prepare_build import sha

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source = args.source.resolve(strict=True)
out = args.output.absolute()
out.mkdir(mode=0o700, parents=True, exist_ok=False)
original = sha(source)
image = out / 'rootfs.ext4'
shutil.copyfile(source, image)
subprocess.run(['debugfs', '-w', '-R', 'symlink /usr/share/clamav /var/lib/clamav', str(image)], check=True)
inspection = subprocess.check_output(['debugfs', '-R', 'stat /usr/share/clamav', str(image)], stderr=subprocess.STDOUT, text=True)
if 'Fast link dest: "/var/lib/clamav"' not in inspection:
    raise SystemExit('database alias verification failed')
if sha(source) != original:
    raise SystemExit('input image changed')
image.chmod(0o444)
(out / 'manifest.json').write_text(json.dumps({'source': str(source), 'source_sha256': original,
    'output_sha256': sha(image), 'recipe': 'immutable /usr/share/clamav -> /var/lib/clamav alias',
    'recipe_sha256': sha(Path(__file__)), 'inspection': inspection}, indent=2) + '\n')
print(image)
