"""Controlled storage faults and disposable collector restart; no host reboot."""
import errno
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import threading

import pytest

from bulldog.anchor_service import AnchorStore, make_server, session_key
from bulldog.audit import AuditIntegrityError, AuditLedger
from bulldog.audit_transport import AnchorIdentity, HTTPSAnchorTransport


@pytest.mark.parametrize('failure', [errno.ENOSPC, errno.EIO])
@pytest.mark.parametrize('stage', ['append', 'head'])
def test_storage_failure_refuses_success_and_preserves_evidence(tmp_path, monkeypatch, failure, stage):
    ledger = AuditLedger(tmp_path / 'ledger')
    ledger.append_event('before', {})
    before = ledger.path.read_bytes()
    original = Path.open

    def failing_open(path, mode='r', *args, **kwargs):
        target = ledger.path if stage == 'append' else ledger.head_path
        if path == target and mode == ('a' if stage == 'append' else 'w'):
            raise OSError(failure, os.strerror(failure))
        return original(path, mode, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'open', failing_open)
        with pytest.raises(OSError) as error:
            ledger.append_event('interrupted', {})
        assert error.value.errno == failure
    reopened = AuditLedger(ledger.path)
    if stage == 'append':
        assert ledger.path.read_bytes() == before
        assert reopened.verify().valid
        reopened.append_event('recovered', {})
        assert reopened.verify().records == 2
    else:
        retained = ledger.path.read_bytes()
        assert retained.startswith(before) and len(retained) > len(before)
        assert not reopened.verify().valid
        with pytest.raises(AuditIntegrityError):
            reopened.append_event('must-not-advance', {})
        assert ledger.path.read_bytes() == retained


def test_storage_budget_refuses_append_without_partial_record(tmp_path):
    ledger = AuditLedger(tmp_path / 'ledger')
    ledger.append_event('before', {})
    before = ledger.path.read_bytes()
    bounded = AuditLedger(ledger.path, max_ledger_bytes=len(before))
    with pytest.raises(AuditIntegrityError, match='storage budget'):
        bounded.append_event('over-budget', {})
    assert bounded.verify().valid and ledger.path.read_bytes() == before


def test_worker_exit_releases_lock_and_retains_pending_plan(tmp_path):
    # This child exits itself; no signals or process-group operations are used.
    code = '''
import os, sys
from bulldog.audit import AuditLedger
ledger = AuditLedger(sys.argv[1])
ledger.append_event('agent_identity', {'id': 'restart-fixture'})
ledger.append_event('agent_plan', {'step': 0, 'tool': 'inspect'})
os._exit(75)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'))
    path = tmp_path / 'ledger'
    child = subprocess.run([sys.executable, '-c', code, str(path)], env=env, timeout=10)
    assert child.returncode == 75
    from tools.governed_agent import records, recover
    from bulldog.session_guard import SessionGuard
    ledger = AuditLedger(path)
    _, plans, done = recover(records(ledger), {'id': 'restart-fixture'}, SessionGuard())
    assert plans == {0: {'step': 0, 'tool': 'inspect'}} and not done
    ledger.append_event('agent_result', {'step': 0, 'tool': 'inspect'})
    assert len(recover(records(AuditLedger(path)), {'id': 'restart-fixture'}, SessionGuard())[2]) == 1


@pytest.mark.skipif(not shutil.which('openssl'), reason='openssl needed for disposable TLS')
def test_tls_collector_outage_restart_and_explicit_reconciliation(tmp_path):
    tmp_path.chmod(0o700)
    cert, keyfile = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                    '-keyout', str(keyfile), '-out', str(cert)], check=True, capture_output=True, timeout=15)
    master, session = secrets.token_bytes(32), secrets.token_hex(32)
    identity = AnchorIdentity(session, session_key(master, session))
    database = tmp_path / 'collector.sqlite'

    def start():
        store = AnchorStore(database, master)
        server = make_server(store, ('127.0.0.1', 0))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        transport = HTTPSAnchorTransport(f'https://localhost:{server.server_port}/v1/checkpoints',
                                         identity, test_ca=cert, timeout=1)
        return store, server, thread, transport

    def stop(server, thread):
        # Only the server/thread constructed inside this temporary fixture.
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()

    store, server, thread, transport = start()
    ledger = AuditLedger(tmp_path / 'ledger', transport=transport)
    try:
        ledger.append_event('before-outage', {})
    finally:
        stop(server, thread)
    with pytest.raises(AuditIntegrityError, match='delivery failed'):
        ledger.append_event('pending-checkpoint', {})
    retained = ledger.path.read_bytes()
    with pytest.raises(AuditIntegrityError):
        ledger.append_event('must-not-advance', {})
    assert ledger.path.read_bytes() == retained
    store, server, thread, transport = start()
    try:
        recovered = AuditLedger(ledger.path, transport=transport)
        assert not recovered.verify().valid
        recovered.reconcile_remote()
        assert recovered.verify().valid and recovered.path.read_bytes() == retained
        recovered.reconcile_remote()  # Latest checkpoint retry is idempotent.
        recovered.append_event('after-restart', {})
        with store.connect() as db:
            assert db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0] == 3
        check = recovered.verify()
        assert check.valid and check.records == 3
        identity.check_ack(json.loads(recovered.remote_checkpoint_path.read_text()), 3, check.head_hash)
    finally:
        stop(server, thread)
