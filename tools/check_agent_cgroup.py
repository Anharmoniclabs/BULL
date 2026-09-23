#!/usr/bin/env python3
"""Harmless live check that a dedicated cgroup refuses a fork at its process limit."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from bulldog.cgroup_scope import CgroupV2Scope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--enter-coordinator', action='store_true')
    args = parser.parse_args()
    parent = args.parent.resolve(strict=True)
    if args.enter_coordinator:
        # Only this dedicated CLI process moves; parent/chat processes stay put.
        (parent / 'coordinator/cgroup.procs').write_text(str(os.getpid()))
    with CgroupV2Scope(parent, memory_bytes=32*1024*1024, processes=1,
                       cpu_quota_us=100000, name_prefix='bull-agent-limit-check') as scope:
        code = """import errno,json,subprocess,sys
from pathlib import Path
blocked = False
try:
    subprocess.run(['/usr/bin/true'], check=True)
except OSError as exc:
    if exc.errno != errno.EAGAIN:
        raise
    blocked = True
root = Path(sys.argv[1])
print(json.dumps({'limit': (root/'pids.max').read_text().strip(),
                  'current': (root/'pids.current').read_text().strip(),
                  'second_process_blocked': blocked}))
"""
        child = subprocess.run([sys.executable, '-I', '-c', code, str(scope.path)],
                               preexec_fn=scope.attach_current, capture_output=True,
                               text=True, check=True, timeout=10)
        report = json.loads(child.stdout)
    report['status'] = 'PASS' if report['limit'] == '1' and report['current'] == '1' and report['second_process_blocked'] else 'FAIL'
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
