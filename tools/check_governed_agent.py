#!/usr/bin/env python3
"""Run dedicated worker crash/recovery cases and a measured local-model soak."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from tools.audit_governed_agent import inspect
from tools.deployment_setup import read_config, private_read
from bulldog.anchor_service import session_key
from bulldog.audit_transport import AnchorIdentity


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--deployment', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--steps', type=int, default=100)
    p.add_argument('--interval', type=float, default=5)
    p.add_argument('--max-seconds', type=float, default=7200)
    p.add_argument('--model', default='qwen2.5:1.5b-instruct')
    p.add_argument('--enter-coordinator', action='store_true')
    args = p.parse_args()
    if args.steps < 2:
        p.error('at least two soak steps required')
    state, config = read_config(args.deployment.resolve())
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = state / 'audit/ledger.jsonl'
    done = inspect(ledger)['completed_steps'] if ledger.exists() else 0
    base = [sys.executable, str(ROOT / 'tools/governed_agent.py'), '--deployment', str(state), '--model', args.model]
    if args.enter_coordinator:
        base += ['--enter-coordinator']
    phases = [('after-plan', 75, ['--steps', str(done + 1), '--fault', 'after-plan']),
              ('after-effect', 76, ['--steps', str(done + 1), '--fault', 'after-effect']),
              ('soak', 0, ['--steps', str(done + args.steps), '--interval', str(args.interval),
                           '--max-seconds', str(args.max_seconds), '--credential-check'])]
    results = []
    started = time.monotonic()
    for name, expected, options in phases:
        with (out / (name + '.log')).open('w') as log:
            # Each invocation is a dedicated CLI worker. Faults exit that worker
            # itself; no process-name matching, group signals or service restart.
            result = subprocess.run(base + options, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        results.append({'phase': name, 'returncode': result.returncode, 'expected': expected})
        print(json.dumps(results[-1]), flush=True)
        if result.returncode != expected:
            break
    report = {'status': 'FAIL', 'phases': results, 'elapsed_seconds': time.monotonic() - started}
    if ledger.exists():
        shutil.copyfile(ledger, out / 'ledger.jsonl')
        audit = inspect(out / 'ledger.jsonl')
        report['audit'] = audit
        receipt = json.loads(private_read(state / 'audit/ledger.jsonl.remote'))
        identity = AnchorIdentity(config['audit_session'], session_key(
            private_read(state / 'secrets/collector.key'), config['audit_session']))
        identity.check_ack(receipt, audit['records'], audit['head_hash'])
        (out / 'collector-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        report['authenticated_collector_receipt_verified'] = True
        passed = (len(results) == 3 and all(r['returncode'] == r['expected'] for r in results)
                  and audit['completed_steps'] == done + args.steps and audit['pending_steps'] == 0
                  and audit['recovery_events'] >= 2 and audit['credential_denials'] >= 1
                  and audit['tools_used'] == ['checksum', 'inspect'])
        report['status'] = 'PASS' if passed else 'FAIL'
    report['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    report['source_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT))
    # Public evidence only: no deployment config, keys, sockets or environment.
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    hashes = {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in out.iterdir() if f.is_file()}
    (out / 'SHA256SUMS.json').write_text(json.dumps(hashes, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json')}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
