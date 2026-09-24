"""Launch the isolated sensor and bounded loopback relays in a dedicated Codespace."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT = r'''
import os, pathlib, socket
status = pathlib.Path('/proc/self/status').read_text()
fields = dict(line.split(':',1) for line in status.splitlines() if ':' in line)
assert os.getuid() != 0, 'must be non-root'
assert fields['NoNewPrivs'].strip() == '1', 'NoNewPrivs missing'
assert int(fields['CapEff'].strip(),16) == 0, 'capabilities retained'
assert fields['Seccomp'].strip() == '2', 'seccomp missing'
assert not pathlib.Path('/var/run/docker.sock').exists(), 'Docker socket exposed'
assert set(os.listdir('/sys/class/net')) == {'lo'}, 'unexpected network interface'
assert not any(k in os.environ for k in ('GITHUB_TOKEN','GH_TOKEN','OPENAI_API_KEY','SSH_AUTH_SOCK')), 'host credentials exposed'
try:
    pathlib.Path('/app/probe-write').write_text('probe')
except OSError:
    pass
else:
    raise AssertionError('application filesystem writable')
s=socket.socket(); s.settimeout(1)
try:
    s.connect(('192.0.2.1',443))
except OSError:
    pass
else:
    raise AssertionError('outbound connection succeeded')
finally:
    s.close()
print('PASS: non-root, no capabilities, no-new-privileges, seccomp, readonly app, no external network interface, no inherited credential variables')
'''


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def port_not_registered(error):
    message = (error.stderr or '') + (error.stdout or '')
    return '404' in message and 'tunnel port' in message.lower()


def visibility(name, port, level, *, missing_ok=False):
    try:
        command('gh', 'codespace', 'ports', 'visibility', f'{port}:{level}',
                '-c', name, capture_output=True, timeout=15)
        return True
    except subprocess.CalledProcessError as error:
        if missing_ok and port_not_registered(error):
            return False
        raise


async def wait_for_private_ports(name, *, attempts=30):
    pending = {8080, 8081}
    for attempt in range(attempts):
        for port in sorted(pending):
            if await asyncio.to_thread(visibility, name, port, 'private', missing_ok=True):
                pending.remove(port)
        if not pending:
            return
        if attempt == 0:
            print('Waiting for Codespaces to register ports 8080 and 8081. '
                  'If they do not appear automatically, open Ports → Add Port and add both. '
                  'The sensor remains disconnected until both are private.', flush=True)
        if attempt + 1 < attempts:
            await asyncio.sleep(2)
    raise RuntimeError('Codespaces has not registered ports ' + ', '.join(map(str, sorted(pending)))
                       + '. Add them in the Ports panel, then rerun the launcher. No sensor traffic was admitted.')


async def relay(port, socket_path, stop_after=None, *, ready=None, enabled=None):
    active = 0
    recent = []

    async def client(reader, writer):
        nonlocal active
        if enabled is not None and not enabled.is_set():
            writer.close()
            return
        now = time.monotonic()
        recent[:] = [t for t in recent if now - t < 1]
        if active >= 12 or len(recent) >= 10:
            writer.close()
            return
        recent.append(now)
        active += 1
        upstream = None
        pumps = []
        try:
            incoming, upstream = await asyncio.open_unix_connection(str(socket_path))

            async def copy(src, dst, budget):
                used = 0
                while True:
                    chunk = await src.read(min(8192, budget - used + 1))
                    if not chunk:
                        try:
                            dst.write_eof()
                        except (OSError, NotImplementedError):
                            pass
                        return
                    used += len(chunk)
                    if used > budget:
                        raise ValueError('relay byte budget exceeded')
                    dst.write(chunk)
                    await dst.drain()

            pumps = [asyncio.create_task(copy(reader, upstream, 32768)),
                     asyncio.create_task(copy(incoming, writer, 4 * 1024 * 1024))]
            await asyncio.wait_for(asyncio.gather(*pumps), timeout=10)
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            for task in pumps:
                task.cancel()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            if upstream:
                upstream.close()
            writer.close()
            active -= 1

    server = await asyncio.start_server(client, '127.0.0.1', port, limit=32768)
    async with server:
        if ready is not None:
            ready.set()
        if stop_after:
            if enabled is not None:
                await enabled.wait()
            await asyncio.sleep(stop_after)
        else:
            await server.serve_forever()


async def run_relays(state, duration, *, public_http=False):
    enabled = asyncio.Event()
    ready = [asyncio.Event(), asyncio.Event()]
    name = os.environ['CODESPACE_NAME']
    async def capture():
        await relay(8080, state / 'capture.sock', duration, ready=ready[0], enabled=enabled)
        await asyncio.to_thread(visibility, name, 8080, 'private', missing_ok=True)
    tasks = [asyncio.create_task(capture()), asyncio.create_task(
        relay(8081, state / 'observer.sock', ready=ready[1], enabled=enabled))]
    async def activate():
        await asyncio.gather(*(event.wait() for event in ready))
        # Printing localhost URLs allows VS Code's automatic forwarding to
        # register the listening ports. Neither relay can yet reach the sensor.
        print('Registering decoy: http://127.0.0.1:8080', flush=True)
        print('Registering observer: http://127.0.0.1:8081', flush=True)
        await wait_for_private_ports(name)
        if public_http:
            await asyncio.to_thread(visibility, name, 8080, 'public')
        enabled.set()
        print(f'Decoy: port 8080 ({"public" if public_http else "private"}); '
              'dashboard: port 8081 (private). Ready.', flush=True)
    tasks.append(asyncio.create_task(activate()))
    try:
        await asyncio.gather(*tasks)
    finally:
        enabled.clear()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--duration', type=int, default=3600)
    parser.add_argument('--public-http', action='store_true',
                        help='Explicitly expose ONLY the bounded HTTP decoy port in this Codespace')
    args = parser.parse_args()
    if not 60 <= args.duration <= 7200:
        parser.error('duration must be 60–7200 seconds')
    if not os.environ.get('CODESPACES') or not os.environ.get('CODESPACE_NAME'):
        parser.error('Use a dedicated GitHub Codespace; this launcher does not expose other hosts')
    if os.getuid() == 0:
        parser.error('Run as the ordinary Codespace user, not root')
    if not shutil.which('docker') or not shutil.which('gh'):
        parser.error('Docker and GitHub CLI must be installed; there is no uncontained fallback')
    name = os.environ['CODESPACE_NAME']
    command('docker', 'info', stdout=subprocess.DEVNULL)
    state = ROOT / '.bull-honeypot' / time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(state.parent, 0o700)
    token_path = state / 'observer.token'
    fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(secrets.token_urlsafe(48))
    source_commit = command('git', '-C', str(ROOT), 'rev-parse', 'HEAD', capture_output=True).stdout.strip()
    digest = hashlib.sha256()
    for folder in ('src/bulldog', 'tools/honeypot'):
        for p in sorted((ROOT / folder).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                digest.update(str(p.relative_to(ROOT)).encode() + b'\0' + p.read_bytes())
    revision = source_commit + ':tree-sha256:' + digest.hexdigest()
    container = 'bull-honeypot-' + secrets.token_hex(4)
    try:
        with tempfile.TemporaryDirectory(prefix='bull-honeypot-build-') as temp:
            context = Path(temp)
            shutil.copytree(ROOT / 'src/bulldog', context / 'src/bulldog',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            for file in ('sensor.py', 'dashboard.html', 'test_sensor.py', 'Dockerfile'):
                shutil.copy2(ROOT / 'tools/honeypot' / file, context / file)
            command('docker', 'build', '--network=none', '-t', container, str(context))
        command('docker', 'run', '--detach', '--rm', '--name', container,
                '--network=none', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true', '--memory=128m', '--memory-swap=128m',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',
                '--cpus=0.5', '--pids-limit=32', '--ulimit', 'nofile=128:128',
                '--user', f'{os.getuid()}:{os.getgid()}',
                '--mount', f'type=bind,src={state},dst=/state',
                '--env', f'BULL_SOURCE_REVISION={revision}', container,
                'python', '/app/sensor.py', '--state', '/state', '--duration', str(args.duration),
                stdout=subprocess.DEVNULL)
        result = command('docker', 'exec', '-i', container, 'python', '-c', PREFLIGHT,
                         capture_output=True)
        # Run the full suite INSIDE the restricted container. A missing feature
        # is a failed launch, never a reason to weaken the boundary.
        suite = command('docker', 'exec', container, 'python', '/app/test_sensor.py',
                        capture_output=True)
        (state / 'integration-tests.log').write_text(suite.stdout + suite.stderr)
        inspect = json.loads(command('docker', 'inspect', container, capture_output=True).stdout)[0]
        host = inspect['HostConfig']
        if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs']
                and 'ALL' in host['CapDrop'] and host['Memory'] == 128 * 1024 * 1024):
            raise RuntimeError('container configuration preflight failed')
        for _ in range(50):
            if (state / 'capture.sock').exists() and (state / 'observer.sock').exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('sensor sockets not ready')
        (state / 'preflight.json').write_text(json.dumps({'passed': True, 'source': revision,
            'image_id': inspect['Image'], 'network': 'none', 'read_only': True,
            'public_http_requested': args.public_http, 'checks': result.stdout.strip()}, indent=2))
        print(result.stdout.strip())
        print(f'Observer token: {token_path} (paste its contents in the private dashboard).')
        print(f'Evidence: {state}. Capture stops after {args.duration} seconds. Ctrl-C stops both relays.')
        asyncio.run(run_relays(state, args.duration, public_http=args.public_http))
    finally:
        for port in (8080, 8081):
            try:
                visibility(name, port, 'private', missing_ok=True)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                print(f'Could not reset port {port}; check its visibility in the Ports panel.', file=sys.stderr)
        subprocess.run(['docker', 'stop', '-t', '3', container], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as error:
        print(error.stderr or error.stdout or str(error), file=sys.stderr)
        raise SystemExit(1)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
