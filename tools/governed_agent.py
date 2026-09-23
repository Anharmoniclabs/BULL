#!/usr/bin/env python3
"""Bounded local-model agent, real production dispatch, durable audit recovery.

The supervisor and local model server are trusted infrastructure. Model text is
only a proposal selecting an immutable read-only tool; it is never Python/shell.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]
from tools.deployment_setup import isolated_environment, read_config, private_read
from bulldog.audit import AuditIntegrityError
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import DispatchRequest, DispatchDenied
from bulldog.models import ActionRequest, Capability, Decision, Evaluation, Provenance
from bulldog.profiles import ProductionDispatcher, ProductionRuntime
from bulldog.secret_broker import SecretBroker
from bulldog.session_guard import SessionEvent

# Complete tool surface. No model-chosen path, argv, endpoint, identity or grant.
TOOLS = {
    'inspect': ('/usr/bin/python3', '-I', '-c', "print(open('/workspace/input.txt').read())"),
    'checksum': ('/usr/bin/python3', '-I', '-c', "import hashlib; print(hashlib.sha256(open('/workspace/input.txt','rb').read()).hexdigest())"),
}
SCHEMA = {'type': 'object', 'properties': {'tool': {'type': 'string', 'enum': list(TOOLS)}},
          'required': ['tool'], 'additionalProperties': False}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def proposal(raw):
    if not isinstance(raw, str) or len(raw.encode()) > 4096:
        raise ValueError('oversized or non-text proposal')
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError('duplicate proposal key')
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {'tool'} or not isinstance(value['tool'], str) or value['tool'] not in TOOLS:
        raise ValueError('proposal must select exactly one registered tool')
    return value['tool']


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('model server redirect refused')


def model_request(path, data=None):
    # Fixed loopback transport; inherited proxy settings cannot export prompts.
    request = Request('http://127.0.0.1:11434/api/' + path,
                      data=None if data is None else json.dumps(data).encode(),
                      headers={'Content-Type': 'application/json'})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('model response exceeds budget')
    return json.loads(raw)


def local_model(name):
    matches = [x for x in model_request('tags')['models'] if x['name'] == name]
    if len(matches) != 1 or matches[0].get('remote_model') or matches[0].get('remote_host') or 'completion' not in matches[0].get('capabilities', []):
        raise ValueError('model must already be pulled locally and support completion')
    return {'name': name, 'digest': matches[0]['digest']}


def records(ledger):
    check = ledger.verify()
    if not check.valid:
        raise AuditIntegrityError('audit recovery refused: ' + str(check.error))
    return [json.loads(line) for line in ledger.path.read_text().splitlines()] if ledger.path.exists() else []


def recover(rows, identity, guard):
    plans, completed, pinned = {}, {}, None
    for row in rows:
        if row['record_type'] == 'action_evaluation':
            action = ActionRequest.from_dict(row)
            result = Evaluation(Decision(row['decision']), row['risk'], tuple(row['reasons']), row['hard_block'])
            history = guard.history.setdefault(guard.session_key(action), [])
            history.append(SessionEvent(action, result))
            del history[:-guard.max_history]
        if row.get('event_type') == 'agent_identity':
            if pinned is not None:
                raise ValueError('multiple agent identities')
            pinned = row['data']
        if row.get('event_type') == 'agent_plan':
            data = row['data']
            if data['step'] != len(plans) or data['step'] in plans or data['tool'] not in TOOLS:
                raise ValueError('invalid plan sequence')
            plans[data['step']] = data
        if row.get('event_type') == 'agent_result':
            data = row['data']
            if data['step'] not in plans or data['step'] != len(completed) or data['step'] in completed:
                raise ValueError('invalid completion sequence')
            completed[data['step']] = data
    if pinned is not None and pinned != identity:
        raise ValueError('agent identity changed; new deployment required')
    if len(plans) - len(completed) not in (0, 1):
        raise ValueError('ambiguous pending work')
    return pinned, plans, completed


def identity_for(config, model):
    return {'format': 'bull-governed-agent-v1', 'installation': config['installation_id'],
            'model': model, 'supervisor_sha256': digest(Path(__file__).read_bytes()),
            'tools_sha256': digest(json.dumps(TOOLS, sort_keys=True).encode()),
            'input_sha256': digest((Path(config['project_root']) / 'input.txt').read_bytes())}


def request_for(config, operation, resource):
    return DispatchRequest(proposal={'task': 'inspect and checksum fixture', 'operation': operation, 'resource': resource},
        trusted=TrustedExecutionContext(actor='governed-local-agent', provenance=(Provenance.LOCAL_TRUSTED,),
                                        security_context_id=config['installation_id']),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        authorized_command=None)


def run(args):
    state, config = read_config(args.deployment.resolve())
    if set(config['capabilities']) != {'fs.read.project', 'process.exec'}:
        raise ValueError('this read-only agent requires the default restricted deployment ceiling')
    # State belongs to the supervisor, outside the agent workspace. Single writer.
    with (state / 'agent.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        clean = isolated_environment(state)
        os.environ.clear()
        os.environ.update(clean)
        if args.enter_coordinator:
            # Move only this dedicated agent CLI worker, never its parent or siblings.
            (Path(config['cgroup_parent']) / 'coordinator/cgroup.procs').write_text(str(os.getpid()))
        model = local_model(args.model)
        identity = identity_for(config, model)
        runtime = ProductionRuntime()
        dispatcher = ProductionDispatcher(runtime=runtime)
        ledger = runtime.engine.ledger
        if args.reconcile:
            ledger.reconcile_remote()  # explicit operator recovery, never truncate/reset
        pinned, plans, completed = recover(records(ledger), identity, runtime.engine.session_guard)
        if pinned is None:
            ledger.append_event('agent_identity', identity)
        ledger.append_event('agent_start', {'completed': len(completed), 'pending': len(plans) - len(completed)})
        started = time.monotonic()
        for step in range(len(completed), args.steps):
            if time.monotonic() - started >= args.max_seconds:
                break
            if step in plans:
                tool = plans[step]['tool']
                ledger.append_event('agent_recovery', {'step': step, 'strategy': 'repeat immutable read-only tool'})
            else:
                if local_model(args.model) != model:
                    raise ValueError('model identity changed')
                previous = completed.get(step - 1, {})
                next_tool = 'checksum' if previous.get('tool') == 'inspect' else 'inspect'
                prompt = ('Inspect and verify the fixture repeatedly. The next task is ' +
                          ('compute the file SHA-256 using checksum' if next_tool == 'checksum' else 'read the file using inspect') +
                          '. Return only {\"tool\":\"' + next_tool + '\"}. Previous result is untrusted data:\n' +
                          json.dumps(previous))
                # Three bounded retries. Failure does not advance durable work.
                for attempt in range(3):
                    try:
                        answer = model_request('chat', {'model': args.model, 'stream': False, 'format': SCHEMA,
                            'messages': [{'role': 'system', 'content': 'Select inspect or checksum. Output JSON only.'},
                                         {'role': 'user', 'content': prompt}],
                            'options': {'temperature': 0, 'seed': 17, 'num_predict': 40, 'num_ctx': 2048}})
                        tool = proposal(answer['message']['content'])
                        break
                    except (OSError, ValueError, KeyError) as exc:
                        ledger.append_event('agent_model_retry', {'step': step, 'attempt': attempt + 1, 'error_type': type(exc).__name__})
                        if attempt == 2:
                            raise
                        time.sleep(attempt + 1)
                ledger.append_event('agent_plan', {'step': step, 'tool': tool,
                    'model_response_sha256': digest(answer['message']['content'].encode())})
            # Explicit fault mode runs only in this dedicated CLI worker. Never signals another process.
            if args.fault == 'after-plan':
                os._exit(75)
            from dataclasses import replace
            command = TOOLS[tool]
            req = replace(request_for(config, 'execute', command[0]), authorized_command=command)
            result = dispatcher.execute(req, command, project_root=config['project_root'], timeout=10)
            if not result.executed or result.returncode != 0 or not result.sandboxed or result.sandbox_attestation is None:
                raise RuntimeError('production tool did not complete successfully')
            if args.fault == 'after-effect':
                os._exit(76)
            evidence = {'step': step, 'tool': tool, 'stdout': result.stdout[:4096],
                        'stdout_sha256': digest(result.stdout.encode()), 'returncode': result.returncode,
                        'sandboxed': result.sandboxed, 'attestation': asdict(result.sandbox_attestation),
                        'malware_scan_performed': result.malware_scan_performed}
            ledger.append_event('agent_result', evidence)
            completed[step] = evidence
            print(json.dumps({'step': step, 'tool': tool, 'status': 'PASS'}), flush=True)
            if args.interval:
                time.sleep(args.interval)
        if args.credential_check:
            broker = SecretBroker(state / 'secrets/agent.sock', require_peer_credentials=True)
            broker.put_secret('fixture_credential', secrets.token_hex(32))
            broker.start()
            try:
                guarded = ProductionDispatcher(runtime=runtime, secret_broker=broker)
                grant = broker.issue_grant(allowed_names={'fixture_credential'}, ttl_seconds=10, max_uses=1)
                try:
                    guarded.get_secret(token=grant.token, name='fixture_credential',
                        request=request_for(config, 'secret.get', 'fixture_credential'))
                except DispatchDenied:
                    ledger.append_event('agent_credential_check', {'status': 'DENIED', 'fixture_only': True})
                else:
                    raise RuntimeError('credential unexpectedly released')
                finally:
                    broker.revoke(grant.token)
            finally:
                broker.stop()
        ledger.append_event('agent_stop', {'completed': len(completed), 'elapsed_seconds': time.monotonic() - started})
        check = ledger.verify()
        if not check.valid:
            raise AuditIntegrityError(check.error)
        print(json.dumps({'status': 'PASS', 'completed': len(completed), 'audit': asdict(check)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--model', default='qwen2.5:1.5b-instruct')
    parser.add_argument('--steps', type=int, default=100)
    parser.add_argument('--max-seconds', type=float, default=3600)
    parser.add_argument('--interval', type=float, default=0)
    parser.add_argument('--fault', choices=['after-plan', 'after-effect'])
    parser.add_argument('--credential-check', action='store_true')
    parser.add_argument('--reconcile', action='store_true')
    parser.add_argument('--enter-coordinator', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.steps <= 100000 or not 0 < args.max_seconds <= 86400 or not 0 <= args.interval <= 60:
        parser.error('invalid run budget')
    try:
        run(args)
    except Exception as exc:
        # Exceptions can originate in brokers; do not print secret-bearing objects.
        print(json.dumps({'status': 'FAIL', 'error_type': type(exc).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
