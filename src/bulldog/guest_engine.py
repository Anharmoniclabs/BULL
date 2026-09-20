"""One-shot trusted guest supervisor; workload authority is deployment-owned."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from .anchor_service import AnchorError, canonical, decode, session_key, verify
from .audit_transport import AnchorIdentity, bootstrap_guest_relay
from .canonicalizer import TrustedExecutionContext
from .dispatcher import DispatchDenied, DispatchRequest
from .microvm_protocol import SessionChannel
from .models import Capability, Provenance
from .profiles import ProductionDispatcher, ProductionRuntime
from .secure_fs import open_beneath, trusted_root_fd


def open_port(name: str) -> int:
    matches = [p.parent for p in Path('/sys/class/virtio-ports').glob('*/name')
               if p.read_text().strip() == name]
    if len(matches) != 1:
        raise AnchorError('missing or ambiguous dedicated virtio port: ' + name)
    major, minor = map(int, (matches[0] / 'dev').read_text().split(':'))
    path = Path('/dev') / matches[0].name
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(major, minor):
        os.close(fd)
        raise AnchorError('virtio device identity mismatch')
    os.fchmod(fd, 0o600)
    return fd


def load_authority(runtime: Path) -> dict:
    """Read only the host-provisioned immutable deployment, never workspace data."""
    with trusted_root_fd(runtime) as root_fd:
        fd = open_beneath(root_fd, 'deployment/session.json')
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 65536
                or info.st_mode & 0o022):
            raise AnchorError('invalid session authority file')
        authority = decode(stream.read(65537))
    required = {'session', 'control_key', 'audit_master', 'request', 'environment', 'expires', 'mac'}
    if (set(authority) != required or not isinstance(authority['session'], str)
            or not re.fullmatch('[a-f0-9]{64}', authority['session'])):
        raise AnchorError('invalid session authority schema')
    key = bytes.fromhex(authority['control_key'])
    if len(key) != 32:
        raise AnchorError('invalid control key')
    if len(bytes.fromhex(authority['audit_master'])) != 32:
        raise AnchorError('invalid audit authority')
    verify(authority, key, purpose='guest-deployment')
    if type(authority['expires']) is not int or not time.time() < authority['expires'] <= time.time() + 3600:
        raise AnchorError('session authority expired or lifetime exceeds one hour')
    request = authority['request']
    if (not isinstance(request, dict) or set(request) != {'argv', 'capabilities', 'timeout'}
            or not isinstance(request['argv'], list) or not 1 <= len(request['argv']) <= 64
            or any(not isinstance(arg, str) or '\0' in arg or len(arg) > 4096 for arg in request['argv'])
            or not request['argv'][0].startswith('/')
            or type(request['timeout']) not in {int, float} or not 0 < request['timeout'] <= 30
            or not isinstance(request['capabilities'], list)):
        raise AnchorError('invalid bounded one-shot request')
    frozenset(Capability(value) for value in request['capabilities'])
    return authority


def run_session(workspace: Path, runtime_root: Path) -> None:
    for path in (workspace, runtime_root):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise AnchorError('guest input and runtime mounts must be read-only')
    authority = load_authority(runtime_root)
    session = authority['session']
    # Environment is a trusted deployment input. No model fields are applied.
    env = authority['environment']
    allowed = {'BULL_SECCOMP_PROFILE', 'BULL_INTEGRITY_MANIFEST', 'BULL_INTEGRITY_MANIFEST_KEY',
               'BULL_POLICY_BUNDLE', 'BULL_POLICY_BUNDLE_KEY', 'BULL_AUDIT_LEDGER',
               'BULL_SNAPSHOT_ROOT', 'BULL_CGROUP_PARENT'}
    if not isinstance(env, dict) or set(env) != allowed or any(not isinstance(v, str) for v in env.values()):
        raise AnchorError('invalid deployment environment')
    os.environ.update(env)
    os.environ['BULL_AUDIT_SESSION_ID'] = session
    os.environ['BULL_AUDIT_TRANSPORT'] = 'relay'
    control_fd = open_port('org.bull.control')
    try:
        audit_fd = open_port('org.bull.audit')
    except BaseException:
        os.close(control_fd)
        raise
    channel = SessionChannel(control_fd, session, bytes.fromhex(authority['control_key']), side='guest', timeout=60)
    try:
        bootstrap_guest_relay(audit_fd,
            AnchorIdentity(session, session_key(bytes.fromhex(authority['audit_master']), session)),
            Path(env['BULL_AUDIT_LEDGER']))
        start = time.monotonic()
        runtime = ProductionRuntime()
        dispatcher = ProductionDispatcher(runtime=runtime)
        startup_ms = (time.monotonic() - start) * 1000
        channel.send('ready', {'session': session, 'kernel': os.uname().release,
                               'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                               'supervisor_namespaces': {name: os.readlink('/proc/self/ns/' + name)
                                                         for name in ('pid', 'mnt', 'net', 'user')},
                               'readonly_mounts': ['/workspace', '/bull_runtime'],
                               'backend': 'strict-namespace', 'dispatcher_startup_ms': startup_ms})
        supplied = channel.receive('execute')
        if supplied != authority['request'] or time.time() >= authority['expires']:
            raise AnchorError('request does not match live deployment authority')
        argv = supplied['argv']
        request = DispatchRequest(
            proposal={'task': 'authorized one-shot guest request', 'operation': 'execute', 'resource': argv[0]},
            trusted=TrustedExecutionContext(actor='microvm:' + session, provenance=(Provenance.LOCAL_TRUSTED,),
                                            security_context_id=session),
            granted_capabilities=frozenset(Capability(c) for c in supplied['capabilities']),
            authorized_command=tuple(argv))
        started = time.monotonic()
        try:
            result = dispatcher.execute(request, argv, project_root=workspace, timeout=supplied['timeout'])
            evidence = {'executed': result.executed, 'returncode': result.returncode,
                        'decision': result.evaluation.decision.value, 'sandboxed': result.sandboxed,
                        'malware_scan_performed': result.malware_scan_performed,
                        'sandbox_attestation': asdict(result.sandbox_attestation) if result.sandbox_attestation else None,
                        'sandbox_setup_ms': result.sandbox_setup_ms,
                        'workload_to_reap_ms': result.workload_to_reap_ms,
                        'stdout': result.stdout[:4096], 'stderr': result.stderr[:4096],
                        'stdout_sha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
                        'trace': asdict(result.trace_state) if result.trace_state is not None else None}
        except DispatchDenied as exc:
            evidence = {'executed': False, 'returncode': None, 'decision': 'DENY', 'error': str(exc)[:1024]}
        except subprocess.TimeoutExpired:
            evidence = {'executed': None, 'returncode': None, 'decision': 'TIMEOUT',
                        'error': 'sandbox deadline exceeded; no successful completion'}
        evidence['dispatch_total_ms'] = (time.monotonic() - started) * 1000
        evidence['session'] = session
        evidence['remaining_workload_cgroups'] = [p.name for p in Path(env['BULL_CGROUP_PARENT']).iterdir() if p.is_dir()]
        evidence['remaining_snapshots'] = [p.name for p in Path(env['BULL_SNAPSHOT_ROOT']).iterdir()]
        if evidence['remaining_workload_cgroups'] or evidence['remaining_snapshots']:
            raise AnchorError('workload cleanup incomplete')
        finished = time.monotonic()
        runtime.engine.ledger.append_event('guest_completion', evidence)
        audit = runtime.engine.ledger.verify()
        if not audit.valid:
            raise AnchorError('completion audit verification failed')
        evidence['audit'] = asdict(audit)
        evidence['audit_completion_ms'] = (time.monotonic() - finished) * 1000
        channel.send('result', evidence)
    except Exception as exc:
        # Error is a distinct authenticated operation, never a successful result.
        try:
            channel.send('error', {'type': type(exc).__name__, 'detail': str(exc)[:2048]})
        except Exception:
            pass
        raise
    finally:
        os.close(control_fd)
        os.close(audit_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    args = parser.parse_args()
    if os.getpid() != 1 or args.workspace != Path('/workspace') or args.runtime != Path('/bull_runtime'):
        parser.error('engine requires the guest PID-1 boot contract')
    def interrupted(signum, frame):
        raise InterruptedError('guest supervisor interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        run_session(args.workspace, args.runtime)
    except Exception as exc:
        print('BULL guest session failed: ' + type(exc).__name__, flush=True)
    finally:
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break
        os.sync()
        subprocess.run(['/sbin/reboot', '-f'], timeout=5, check=False)
        while True:
            time.sleep(1)


if __name__ == '__main__':
    main()
