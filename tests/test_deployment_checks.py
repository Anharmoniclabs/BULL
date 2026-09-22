"""Validation-runner contracts. Fixtures here do not qualify hardware or KVM."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from bulldog.anchor_service import AnchorError, AnchorStore, canonical, checkpoint, decode, make_server, session_key
from bulldog.audit_transport import AnchorIdentity, HostAnchorRelay, HTTPSAnchorTransport
from microvm.evidence import ReceiptTransport, anchor_master
from tools import deployment_check as deploy


def test_missing_kvm_is_blocked(monkeypatch):
    monkeypatch.setattr(deploy.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(deploy.platform, 'machine', lambda: 'x86_64')
    def missing(*args):
        raise FileNotFoundError('/dev/kvm')
    monkeypatch.setattr(deploy.os, 'open', missing)
    assert deploy.probe_kvm()['status'] == 'BLOCKED'


@pytest.mark.parametrize('api,expected', [(12, 'PASS'), (11, 'BLOCKED')])
def test_kvm_probe_checks_api_and_closes_descriptors(monkeypatch, api, expected):
    closed, calls = [], []
    monkeypatch.setattr(deploy.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(deploy.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(deploy.os, 'open', lambda *args: 70)
    monkeypatch.setattr(deploy.os, 'fstat', lambda fd: SimpleNamespace(st_mode=stat.S_IFCHR))
    monkeypatch.setattr(deploy.os, 'close', closed.append)
    def ioctl(fd, request, arg):
        calls.append(request)
        return api if request == 0xAE00 else 71
    monkeypatch.setattr(deploy.fcntl, 'ioctl', ioctl)
    assert deploy.probe_kvm()['status'] == expected
    assert closed == ([71, 70] if api == 12 else [70])
    assert calls == ([0xAE00, 0xAE01] if api == 12 else [0xAE00])


def test_asset_manifest_rejects_changed_bytes(tmp_path):
    manifest = tmp_path / 'assets.json'
    values = {}
    for name in ('kernel', 'rootfs', 'firmware'):
        path = tmp_path / name
        path.write_bytes(b'not a boot image; digest fixture only')
        values[name] = {'path': str(path), 'sha256': deploy.digest(path)}
    manifest.write_text(json.dumps(values))
    assert deploy.checked_assets(manifest) == values
    (tmp_path / 'rootfs').write_bytes(b'changed')
    with pytest.raises(ValueError, match='SHA-256 mismatch'):
        deploy.checked_assets(manifest)


def test_private_key_exact_bytes_and_permissions(tmp_path):
    key = tmp_path / 'key'
    key.write_bytes(b'k' * 32 + b'\n')
    key.chmod(0o600)
    assert anchor_master(key) == b'k' * 32 + b'\n'
    key.chmod(0o666)
    with pytest.raises(AnchorError, match='private'):
        anchor_master(key)
    key.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(key)
    with pytest.raises(OSError):
        anchor_master(link)


def test_test_runner_rejects_skipped_evidence(tmp_path, monkeypatch):
    checks = deploy.Checks(tmp_path)
    def skipped(name, argv, **kwargs):
        checks.record(name, 'PASS')
        (tmp_path / (name + '.xml')).write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="1"/></testsuites>')
        return True
    monkeypatch.setattr(checks, 'command', skipped)
    checks.pytest('example', [])
    assert checks.gates['example']['status'] == 'FAIL'


def test_command_timeout_stops_owned_child(tmp_path):
    checks = deploy.Checks(tmp_path)
    pidfile = tmp_path / 'child.pid'
    code = "import os,time,pathlib; pathlib.Path(%r).write_text(str(os.getpid())); time.sleep(30)" % str(pidfile)
    assert checks.command('timeout', [sys.executable, '-c', code], timeout=1) is False
    assert checks.gates['timeout']['status'] == 'FAIL'
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def test_real_tls_relay_correlates_receipt_with_separate_host_key(tmp_path):
    """Real loopback TLS, disposable keys/cert; not an external deployment."""
    tmp_path.chmod(0o700)
    session = secrets.token_hex(32)
    guest_master, external_master = secrets.token_bytes(32), secrets.token_bytes(32)
    guest_key, external_key = session_key(guest_master, session), session_key(external_master, session)
    store = AnchorStore(tmp_path / 'collector.sqlite', external_master)
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=15)
    server = make_server(store, ('127.0.0.1', 0))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    upstream = HTTPSAnchorTransport(f'https://localhost:{server.server_port}/v1/checkpoints',
                                   AnchorIdentity(session, external_key), test_ca=cert)
    receipt = ReceiptTransport(upstream, tmp_path / 'receipt.json')
    relay = HostAnchorRelay(AnchorStore(tmp_path / 'relay.sqlite', guest_master), receipt, session)
    body = {'data': 'bounded relay fixture', 'previous_hash': None}
    record = dict(body, record_hash=hashlib.sha256(canonical(body)).hexdigest())
    try:
        reply = decode(relay.handle(canonical(checkpoint(session, 1, record, guest_key))))
        AnchorIdentity(session, guest_key).check_ack(reply, 1, record['record_hash'])
        ack = receipt.completion(session, {'valid': True, 'records': 1, 'head_hash': record['record_hash']})
        AnchorIdentity(session, external_key).check_ack(ack, 1, record['record_hash'])
        assert json.loads((tmp_path / 'receipt.json').read_text()) == ack
        assert receipt.production_ready is False
        with pytest.raises(AnchorError, match='authentication'):
            AnchorIdentity(session, guest_key).check_ack(ack, 1, record['record_hash'])
        for change in ({'records': 2}, {'head_hash': '0' * 64}, {'valid': False}):
            with pytest.raises(AnchorError):
                receipt.completion(session, {'valid': True, 'records': 1, 'head_hash': record['record_hash'], **change})
        with pytest.raises(AnchorError):
            receipt.completion('f' * 64, {'valid': True, 'records': 1, 'head_hash': record['record_hash']})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_receipt_rejects_invalid_upstream_ack_before_persistence(tmp_path):
    identity = AnchorIdentity('a' * 64, b'k' * 32)
    upstream = SimpleNamespace(identity=identity, production_ready=False, submit=lambda *args: {'accepted': True, 'mac': '0' * 64})
    receipt = ReceiptTransport(upstream, tmp_path / 'receipt.json')
    with pytest.raises(AnchorError):
        receipt.submit(1, {'record_hash': 'b' * 64})
    assert receipt.last_receipt is None
    assert not receipt.receipt_path.exists()
