#!/usr/bin/env python3
"""KVM integration fixture with disposable TLS or an operator-selected collector.

This is test infrastructure, not deployment configuration or certification.
Invoke from the checkout with PYTHONPATH=src.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time

from bulldog.anchor_service import AnchorStore, MAX_FRAME, authenticate, canonical, make_server, session_key
from bulldog.audit_transport import AnchorIdentity, HTTPSAnchorTransport, HostAnchorRelay
from bulldog.integrity import build_integrity_manifest, sign_integrity_manifest
from bulldog.microvm_protocol import RemoteSessionError, SessionChannel
from bulldog.policy_bundle import sign_policy_bundle
from evidence import ReceiptTransport, anchor_master

WORKLOAD = '''import json, os, resource, time
started = time.monotonic_ns()
assert open('/workspace/input.txt').read() == 'deterministic input\\n'
for path in ('/workspace/input.txt', '/bull_runtime/__init__.py'):
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError:
        pass
    else:
        os.close(fd)
        raise AssertionError('write unexpectedly permitted')
assert not os.path.exists('/bull_runtime/deployment/session.json')
assert not any('KEY' in k or 'AUDIT' in k or 'ATTEST' in k for k in os.environ)
assert resource.getrlimit(resource.RLIMIT_AS)[0] == 512 * 1024 * 1024
fds = []
for fd in range(256):
    try:
        os.fstat(fd)
        fds.append(fd)
    except OSError:
        pass
assert fds == [0, 1, 2], fds
print('BULL_STATUS=PASS: workload data only')
print(json.dumps({'checks': 'passed', 'environment_keys': sorted(os.environ),
                  'open_fds': fds, 'memory_limit': resource.getrlimit(resource.RLIMIT_AS)[0],
                  'fixture_duration_ns': time.monotonic_ns() - started}, sort_keys=True))
'''


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n')
    Path(path).chmod(0o600)


def vm_identity(launcher_pid):
    children = Path(f'/proc/{launcher_pid}/task/{launcher_pid}/children').read_text().split()
    if len(children) != 1:
        raise ValueError('ambiguous VM process identity')
    pid = int(children[0])
    command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    if Path(command[0].decode()).name != 'qemu-system-x86_64':
        raise ValueError('launcher child is not the expected QEMU process')
    # starttime is field 22, after the parenthesized comm field. This is host
    # process evidence, with clock-tick resolution, not guest self-report.
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return pid, int(fields[19]) / os.sysconf('SC_CLK_TCK')


def run(args):
    repo = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    session, control_key, master = secrets.token_hex(32), secrets.token_bytes(32), secrets.token_bytes(32)
    identity = AnchorIdentity(session, session_key(master, session))
    runtime, workspace = out / 'runtime', out / 'workspace'
    (runtime / 'src').mkdir(parents=True)
    (runtime / 'bin').mkdir()
    (runtime / 'deployment').mkdir(mode=0o700)
    workspace.mkdir()
    (workspace / 'input.txt').write_text('deterministic input\n')
    shutil.copytree(repo / 'src/bulldog', runtime / 'src/bulldog', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copyfile(repo / 'microvm/guest/bull-engine', runtime / 'bin/bull-engine')
    (runtime / 'bin/bull-engine').chmod(0o755)
    signing_key = secrets.token_hex(32)
    deployment = runtime / 'deployment'
    save(deployment / 'integrity.json', sign_integrity_manifest(build_integrity_manifest(runtime / 'src/bulldog'), signing_key))
    save(deployment / 'policy.json', sign_policy_bundle(allowed_capabilities=['process.exec'], key=signing_key))
    argv = ['/usr/bin/python3', '-I', '-c', WORKLOAD]
    if args.case in {'timeout', 'cancel'}:
        argv = ['/usr/bin/python3', '-I', '-c', 'import time; time.sleep(25)']
    request = {'argv': argv, 'capabilities': [] if args.case == 'denied' else ['process.exec'],
               'timeout': 1 if args.case == 'timeout' else 30}
    environment = {'BULL_SECCOMP_PROFILE': 'strict',
                   'BULL_INTEGRITY_MANIFEST': '/bull_runtime/deployment/integrity.json',
                   'BULL_INTEGRITY_MANIFEST_KEY': signing_key,
                   'BULL_POLICY_BUNDLE': '/bull_runtime/deployment/policy.json',
                   'BULL_POLICY_BUNDLE_KEY': signing_key,
                   'BULL_AUDIT_LEDGER': '/run/bull/audit/ledger.jsonl',
                   'BULL_SNAPSHOT_ROOT': '/run/bull/snapshots',
                   'BULL_CGROUP_PARENT': '/sys/fs/cgroup/workloads'}
    if args.case == 'missing-protection':
        environment['BULL_SECCOMP_PROFILE'] = 'compat'
    save(deployment / 'session.json', authenticate({'session': session, 'control_key': control_key.hex(),
         'audit_master': master.hex(), 'request': request, 'environment': environment,
         'expires': int(time.time()) + 900}, control_key, purpose='guest-deployment'))
    server = server_thread = collector = None
    if args.external_url:
        # The external master stays on the host. The guest gets a separate,
        # disposable relay master; HostAnchorRelay re-signs upstream checkpoints.
        external_identity = AnchorIdentity(session, session_key(anchor_master(args.external_key_file), session))
        upstream = HTTPSAnchorTransport(args.external_url, external_identity)
        if not upstream.production_ready:
            raise ValueError('external collector requires a non-local HTTPS endpoint with system trust')
    else:
        cert, tls_key = out / 'test-cert.pem', out / 'test-key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(tls_key), '-out', str(cert)], check=True, capture_output=True, timeout=15)
        collector = AnchorStore(out / 'collector.sqlite', master)
        server = make_server(collector, ('127.0.0.1', 0))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        upstream = HTTPSAnchorTransport(f'https://localhost:{server.server_port}/v1/checkpoints', identity, test_ca=cert)
    transport = ReceiptTransport(upstream, out / 'collector-receipt.json')
    relay = HostAnchorRelay(AnchorStore(out / 'relay.sqlite', master), transport, session)
    listeners = {}
    errors = []
    for name in ('control', 'audit'):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(out / (name + '.sock')))
        (out / (name + '.sock')).chmod(0o600)
        listener.listen(1)
        listener.settimeout(120)
        listeners[name] = listener
    stop = threading.Event()
    def audit_loop():
        try:
            conn, _ = listeners['audit'].accept()
            with conn:
                conn.settimeout(1)
                frame = bytearray()
                deadline = time.monotonic() + 120
                while not stop.is_set():
                    if time.monotonic() > deadline:
                        raise TimeoutError('audit frame deadline')
                    try:
                        chunk = conn.recv(1)
                    except socket.timeout:
                        continue
                    if not chunk:
                        if frame:
                            raise ValueError('incomplete audit frame')
                        break
                    if chunk == b'\n':
                        conn.sendall(relay.handle(bytes(frame)))
                        frame.clear()
                        deadline = time.monotonic() + 120
                    else:
                        frame.extend(chunk)
                        if len(frame) > MAX_FRAME:
                            raise ValueError('oversized audit frame')
        except Exception as exc:
            if not stop.is_set():
                errors.append(type(exc).__name__ + ': ' + str(exc))
    audit_thread = threading.Thread(target=audit_loop, daemon=True)
    audit_thread.start()
    config = {'APPROVED_WORKSPACE_ROOT': str(out), 'APPROVED_RUNTIME_ROOT': str(out),
              'WORKSPACE': str(workspace), 'RUNTIME_DIR': str(runtime),
              'KERNEL': str(args.kernel.resolve()), 'ROOTFS': str(args.rootfs.resolve()),
              'FIRMWARE': str(args.firmware.resolve()), 'FIRMWARE_SHA256': digest(args.firmware),
              'CONTROL_SOCKET': str(out / 'control.sock'), 'AUDIT_SOCKET': str(out / 'audit.sock'),
              'TIMEOUT_SECONDS': '180'}
    config['CPU_PROFILE'] = args.cpu_profile
    config_path = out / 'deployment.env'
    config_path.write_text(''.join('BULL_MICROVM_' + k + '=' + v + '\n' for k, v in config.items()))
    config_path.chmod(0o600)
    report = {'status': 'FAIL', 'session': session, 'case': args.case,
              'collector': 'external authenticated HTTPS collector' if args.external_url else 'isolated disposable authenticated TLS test collector',
              'external_collector': bool(args.external_url),
              'hardware_attestation': False,
              'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
              'assets': {name: digest(getattr(args, name)) for name in ('kernel', 'rootfs', 'firmware')}}
    sources = {str(path.relative_to(repo)): digest(path)
               for directory in ('src', 'microvm') for path in (repo / directory).rglob('*')
               if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    report['source_tree_sha256'] = hashlib.sha256(canonical(sources)).hexdigest()
    save(out / 'source-files.json', sources)
    child = None
    try:
        started = time.monotonic()
        with (out / 'boot.log').open('wb') as log:
            child = subprocess.Popen([str(repo / 'microvm/run-bull-microvm.sh'), '--config', str(config_path)],
                                     cwd=repo, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            conn, _ = listeners['control'].accept()
            vm_pid, vm_started = vm_identity(child.pid)
            report['qemu_pid'] = vm_pid
            report['host_process_clock_resolution_ms'] = 1000 / os.sysconf('SC_CLK_TCK')
            with conn:
                channel = SessionChannel(conn.fileno(), session, control_key, side='host', timeout=120)
                report['guest_ready'] = channel.receive('ready')
                report['launch_to_dispatcher_ready_ms'] = (time.monotonic() - started) * 1000
                report['vm_start_to_dispatcher_ready_ms'] = (time.clock_gettime(time.CLOCK_BOOTTIME) - vm_started) * 1000
                if args.case == 'missing-protection':
                    raise ValueError('required strict protection gate unexpectedly admitted request')
                request_started = time.monotonic()
                channel.send('execute', request)
                if args.case == 'cancel':
                    # Capture only this launcher's actual QEMU child identity.
                    time.sleep(12)
                    child.terminate()
                    report['qemu_launcher_exit'] = child.wait(timeout=10)
                    if Path(f'/proc/{vm_pid}').exists():
                        raise ValueError('QEMU remains after cancellation')
                    try:
                        channel.receive('result')
                    except Exception:
                        report['cancellation'] = {'qemu_pid': vm_pid, 'qemu_reaped': True,
                                                  'completion_received': False, 'safe_replay': False}
                    else:
                        raise ValueError('cancelled run unexpectedly supplied successful completion')
                    raise VerifiedCancellation()
                result = channel.receive('result')
                report['host_request_to_result_ms'] = (time.monotonic() - request_started) * 1000
                report['result_and_audit_overhead_ms'] = report['host_request_to_result_ms'] - result.get('dispatch_total_ms', 0)
                report['result'] = result
                if result.get('session') != session or not result.get('audit', {}).get('valid'):
                    raise ValueError('incomplete authenticated completion evidence')
                report['completion_receipt'] = transport.completion(session, result['audit'])
                if collector is not None:
                    with collector.connect() as db:
                        accepted = db.execute('SELECT head FROM checkpoints WHERE session=? AND sequence=?',
                                              (session, result['audit'].get('records'))).fetchone()
                    if accepted is None or accepted[0] != result['audit'].get('head_hash'):
                        raise ValueError('completion head was not acknowledged by test collector')
                if args.case == 'allowed':
                    if (result.get('executed') is not True or result.get('returncode') != 0
                            or not result.get('sandboxed') or not result.get('malware_scan_performed')
                            or not result.get('sandbox_attestation')
                            or not result.get('stdout', '').startswith('BULL_STATUS=PASS: workload data only\n')):
                        raise ValueError('allowed workload did not complete with required evidence')
                    fixture = json.loads(result['stdout'].splitlines()[1])
                    if fixture.get('checks') != 'passed' or fixture.get('open_fds') != [0, 1, 2]:
                        raise ValueError('incomplete sandboxed fixture measurements')
                    report['sandboxed_fixture'] = fixture
                elif args.case == 'timeout':
                    if (result.get('decision') != 'TIMEOUT' or result.get('returncode') is not None
                            or result.get('remaining_workload_cgroups') != []
                            or result.get('remaining_snapshots') != []):
                        raise ValueError('timeout did not produce verified cleanup evidence')
                elif result.get('executed') is not False or result.get('decision') != 'DENY':
                    raise ValueError('out-of-policy request was not refused')
            report['qemu_launcher_exit'] = child.wait(timeout=30)
            if report['qemu_launcher_exit'] != 0:
                raise ValueError('VM launcher failed after workload result; inspect boot log')
            if errors:
                raise ValueError('audit relay failed: ' + '; '.join(errors))
            report['status'] = 'PASS'
    except VerifiedCancellation:
        report['status'] = 'PASS'
    except RemoteSessionError as exc:
        report['guest_error'] = exc.payload
        if (args.case == 'missing-protection' and exc.payload.get('type') == 'ProductionGateFailure'
                and 'production requires BULL_SECCOMP_PROFILE=strict' in exc.payload.get('detail', '')):
            report['status'] = 'PASS'
            report['request_admitted'] = False
        else:
            report['error'] = str(exc)
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if child is not None and child.poll() is None:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    report['cleanup_error'] = 'launcher did not finish cancellation'
                    report['status'] = 'FAIL'
        stop.set()
        for listener in listeners.values():
            listener.close()
        audit_thread.join(timeout=2)
        if server is not None:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
        for name in ('control', 'audit'):
            (out / (name + '.sock')).unlink(missing_ok=True)
        save(out / 'report.json', report)
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json')}))
    return 0 if report['status'] == 'PASS' else 1


class VerifiedCancellation(Exception):
    """Internal test control flow after verifying the exact VM was reaped."""


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise InterruptedError('integration interrupted; cleaning up owned VM')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('kernel', 'rootfs', 'firmware', 'output'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--case', choices=('all', 'allowed', 'denied', 'timeout', 'cancel', 'missing-protection'), required=True)
    parser.add_argument('--cpu-profile', choices=('host', 'amd-native-ssbd'), default='host')
    parser.add_argument('--external-url', help='Operator-selected collector; sends checkpoint metadata to this HTTPS endpoint.')
    parser.add_argument('--external-key-file', type=Path, help='Private key file, or use BULL_REMOTE_AUDIT_ANCHOR_KEY.')
    args = parser.parse_args()
    if args.external_key_file and not args.external_url:
        parser.error('--external-key-file requires --external-url')
    if args.case == 'all':
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        reports = []
        for case in ('allowed', 'denied', 'timeout', 'cancel', 'missing-protection'):
            case_args = argparse.Namespace(**vars(args))
            case_args.case, case_args.output = case, args.output / case
            run(case_args)
            reports.append(json.loads((case_args.output / 'report.json').read_text()))
        summary = {'status': 'PASS' if all(r['status'] == 'PASS' for r in reports) else 'FAIL',
                   'scope': 'one-shot KVM integration with external collector' if args.external_url else 'local one-shot KVM integration with disposable TLS test collector',
                   'cases': {r['case']: r['status'] for r in reports},
                   'source_tree_sha256': sorted({r['source_tree_sha256'] for r in reports})}
        if len(summary['source_tree_sha256']) != 1:
            summary['status'] = 'FAIL'
        save(args.output / 'summary.json', summary)
        print(json.dumps(summary))
        raise SystemExit(0 if summary['status'] == 'PASS' else 1)
    raise SystemExit(run(args))
