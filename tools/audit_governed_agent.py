#!/usr/bin/env python3
"""Offline evidence validation. Chain consistency is not independent anchoring proof."""
from __future__ import annotations
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from bulldog.audit import AuditLedger
from tools.governed_agent import TOOLS, recover
from bulldog.session_guard import SessionGuard


def inspect(path, expected_head=None):
    # Read-only validator: do not instantiate a writer or create lock/sidecar files.
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    previous = None
    for i, row in enumerate(rows):
        if row['previous_hash'] != previous or AuditLedger._calculate_hash(row) != row['record_hash']:
            raise ValueError('invalid audit chain at record ' + str(i + 1))
        previous = row['record_hash']
    if expected_head is not None and previous != expected_head:
        raise ValueError('head differs from independently pinned value')
    identities = [r['data'] for r in rows if r.get('event_type') == 'agent_identity']
    if len(identities) != 1:
        raise ValueError('missing or ambiguous agent identity')
    identity = identities[0]
    _, plans, completed = recover(rows, identity, SessionGuard())
    for step, result in completed.items():
        if result['tool'] != plans[step]['tool'] or result['returncode'] != 0 or not result['sandboxed'] or not result['malware_scan_performed']:
            raise ValueError('unsuccessful tool completion')
        att = result['attestation']
        if not all(att.get(k) for k in ('seccomp', 'landlock', 'no_new_privs', 'network_isolated')) or att['seccomp_profile'] != 'strict' or att['pid'] != 1:
            raise ValueError('missing sandbox protections')
        if hashlib.sha256(result['stdout'].encode()).hexdigest() != result['stdout_sha256']:
            raise ValueError('tool output hash mismatch')
        if result['tool'] == 'checksum' and result['stdout'].strip() != identity['input_sha256']:
            raise ValueError('fixture checksum mismatch')
        if result['tool'] == 'inspect' and hashlib.sha256(result['stdout'][:-1].encode()).hexdigest() != identity['input_sha256']:
            raise ValueError('fixture read mismatch')
    events = [r.get('event_type') for r in rows]
    seconds = (datetime.fromisoformat(rows[-1]['timestamp']) - datetime.fromisoformat(rows[0]['timestamp'])).total_seconds()
    return {'status': 'PASS' if completed and len(completed) == len(plans) else 'INCOMPLETE',
            'completed_steps': len(completed), 'pending_steps': len(plans) - len(completed),
            'tools_used': sorted({x['tool'] for x in completed.values()}),
            'recovery_events': events.count('agent_recovery'), 'starts': events.count('agent_start'),
            'credential_denials': sum(r.get('event_type') == 'agent_credential_check' and r['data']['status'] == 'DENIED' for r in rows),
            'records': len(rows), 'head_hash': previous, 'elapsed_seconds': seconds,
            'identity': identity, 'independently_pinned_head': expected_head is not None,
            'scope': 'read-only fixed-tool local model agent; successful credential release and multi-day operation not demonstrated'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ledger', type=Path)
    parser.add_argument('--expected-head')
    args = parser.parse_args()
    try:
        report = inspect(args.ledger, args.expected_head)
        print(json.dumps(report, indent=2))
        return 0 if report['status'] == 'PASS' else 1
    except (ValueError, KeyError, OSError) as exc:
        print(json.dumps({'status': 'FAIL', 'reason': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
