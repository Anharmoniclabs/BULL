#!/usr/bin/env python3
"""Exercise both fixed agent tools and an empty-grant denial on a real deployment."""
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from tools.deployment_setup import isolated_environment, read_config
from tools.governed_agent import TOOLS, request_for
from bulldog.models import Decision
from bulldog.profiles import ProductionDispatcher, ProductionRuntime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--enter-coordinator', action='store_true')
    args = parser.parse_args()
    state, config = read_config(args.deployment.resolve())
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error('evidence must be outside the repository')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = isolated_environment(state)
    os.environ.clear()
    os.environ.update(environment)
    if args.enter_coordinator:
        (Path(config['cgroup_parent']) / 'coordinator/cgroup.procs').write_text(str(os.getpid()))
    runtime = ProductionRuntime()
    dispatcher = ProductionDispatcher(runtime=runtime)
    fixture = (Path(config['project_root']) / 'input.txt').read_bytes()
    cases = {}
    for tool, command in TOOLS.items():
        request = replace(request_for(config, 'execute', command[0]), authorized_command=command)
        result = dispatcher.execute(request, command, project_root=config['project_root'], timeout=10)
        expected = fixture.decode() + '\n' if tool == 'inspect' else hashlib.sha256(fixture).hexdigest() + '\n'
        valid = (result.executed and result.returncode == 0 and result.stdout == expected
                 and result.sandboxed and result.sandbox_attestation is not None and result.malware_scan_performed)
        cases[tool] = {'status': 'PASS' if valid else 'FAIL', 'executed': result.executed,
                       'returncode': result.returncode, 'sandboxed': result.sandboxed}
    command = TOOLS['inspect']
    request = replace(request_for(config, 'execute', command[0]), authorized_command=command,
                      granted_capabilities=frozenset())
    result = dispatcher.execute(request, command, project_root=config['project_root'], timeout=10)
    denied = result.executed is False and result.evaluation.decision == Decision.DENY and not result.stdout
    cases['empty-grants'] = {'status': 'PASS' if denied else 'FAIL', 'executed': result.executed,
                             'decision': result.evaluation.decision.value}
    audit = runtime.engine.ledger.verify()
    report = {'status': 'PASS' if audit.valid and all(c['status'] == 'PASS' for c in cases.values()) else 'FAIL',
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'backend': 'host NamespaceSandbox via ProductionDispatcher', 'cases': cases,
              'audit_valid': audit.valid, 'audit_records': audit.records,
              'scope': 'fixed-tool dispatch integration; no model, MicroVM, or credential-release claim'}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
