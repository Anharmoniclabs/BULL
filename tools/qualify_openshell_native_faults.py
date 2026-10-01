#!/usr/bin/env python3
"""Native Docker/OpenShell delay, reset, restart and next-effect revoke checks.

Requires already-built NVIDIA/OpenShell v0.1.2 source. Uses its own temporary
SQL database/gateway and deletes only sandboxes created by this test run.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from openshell_experiment import Stack, Upstream, build_images, curl, policy_yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--os-src', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    required = ['target/release/openshell', 'target/release/openshell-gateway',
                'target/release/openshell-supervisor',
                'target/x86_64-unknown-linux-musl/release/openshell-sandbox']
    missing = [p for p in required if not (args.os_src / p).is_file()]
    if not shutil.which('docker'): missing.append('docker executable')
    if missing:
        (args.output/'report.json').write_text(json.dumps({'status':'BLOCKED','missing':missing},indent=2))
        print('Native run BLOCKED:', ', '.join(missing)); return 2
    actual = subprocess.check_output(['git','rev-parse','HEAD'],cwd=args.os_src,text=True).strip()
    if actual != '6648bd0c290efbc41ba131ee9831ee45cd431f94':
        raise RuntimeError('Expected pinned NVIDIA/OpenShell v0.1.2; found '+actual)
    args.decision_timeout = .2
    args.fault_file = args.output/'fault.json'
    args.fault_file.write_text('{}')
    up = Upstream().start()
    images = build_images(args.os_src, 'bull-operational')
    stack = Stack(args, args.output, up, images, True)
    rows = []
    def probe(label, fault, expected):
        args.fault_file.write_text(json.dumps(fault))
        marker = 'operational-'+label
        code, elapsed, _ = curl(stack, 'coder', 'api', 'POST', '/v1/records', marker)
        # A late worker cannot resurrect the effect after the caller's deadline.
        if fault.get('delay_ms',0) >= 200: time.sleep(fault['delay_ms']/1000 + .1)
        effects = len(up.posts(marker))
        rows.append({'case':label,'fault':fault,'http':code,'effects':effects,
                     'elapsed_seconds':elapsed,'pass':effects==int(expected)})
        print(json.dumps(rows[-1]),flush=True)
    try:
        stack.start_bull(); stack.start_gateway()
        policy = args.output/'policy.yaml'; policy.write_text(policy_yaml(up))
        done,_ = stack.create('coder',policy)
        if done.returncode: raise RuntimeError(done.stdout+done.stderr)
        for delay in [10,50,100,250,1000,5000]: probe('delay-'+str(delay),{'delay_ms':delay},delay<200)
        probe('reset',{'disconnect':True},False)
        args.fault_file.write_text('{}')
        stack.stop_bull()
        code,elapsed,_=curl(stack,'coder','api','POST','/v1/records','operational-unavailable')
        rows.append({'case':'unavailable','http':code,'effects':len(up.posts('operational-unavailable')),
                     'elapsed_seconds':elapsed,'pass':not up.posts('operational-unavailable')})
        stack.start_bull(); probe('restart',{},True)
        result=stack.admin_call({'cmd':'revoke','sandbox':'coder','capabilities':['network.post']})
        if not result.get('ok'): raise RuntimeError(str(result))
        probe('revoked',{},False)
        stack.stop_bull(); stack.start_bull(); probe('revoked-after-restart',{},False)
        report={'status':'PASS' if all(r['pass'] for r in rows) else 'FAIL', 'cases':rows,
                'scope':'native pinned OpenShell Docker gateway, BULL middleware, observed destination POST effects',
                'exact_native_ocsf_export':'OPEN: native JSONL identity export is not implemented by this runner'}
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        return 0 if report['status']=='PASS' else 1
    finally:
        stack.stop()
        for server in up.servers.values(): server.shutdown(); server.server_close()
if __name__=='__main__': raise SystemExit(main())
