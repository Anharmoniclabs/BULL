import hashlib
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import threading

import pytest

from bulldog.anchor_service import AnchorError, AnchorStore, authenticate, canonical, checkpoint, decode, make_server, session_key
from bulldog.audit_transport import AnchorIdentity, HTTPSAnchorTransport, HostAnchorRelay
from bulldog.audit import AuditLedger, AuditIntegrityError


def record(value="first", previous=None):
    body = {"data": value, "previous_hash": previous}
    return dict(body, record_hash=hashlib.sha256(canonical(body)).hexdigest())


def setup_store(tmp_path, **kwargs):
    tmp_path.chmod(0o700)
    master = secrets.token_bytes(32)
    session = secrets.token_hex(32)
    store = AnchorStore(tmp_path / "audit.sqlite", master, **kwargs)
    return store, master, session, session_key(master, session)


def test_durable_restart_exact_retry_and_conflict(tmp_path):
    store, master, session, key = setup_store(tmp_path)
    first = checkpoint(session, 1, record(), key)
    ack = store.accept(first)
    AnchorIdentity(session, key).check_ack(ack, 1, first["head_hash"])
    restarted = AnchorStore(tmp_path / "audit.sqlite", master)
    assert restarted.accept(first) == ack
    with pytest.raises(AnchorError, match="conflicting"):
        restarted.accept(checkpoint(session, 1, record("changed"), key))
    second = checkpoint(session, 2, record("next", first["head_hash"]), key)
    restarted.accept(second)
    with pytest.raises(AnchorError, match="replay"):
        restarted.accept(first)
    with restarted.connect() as db:
        assert db.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 2


def test_authentication_sequence_hash_and_bounds(tmp_path):
    store, _, session, key = setup_store(tmp_path)
    message = checkpoint(session, 1, record(), key)
    with pytest.raises(AnchorError, match="authentication"):
        store.accept(dict(message, mac="0" * 64))
    with pytest.raises(AnchorError, match="conflicting"):
        store.accept(checkpoint(session, 2, record(), key))
    with pytest.raises(AnchorError, match="hash"):
        store.accept(checkpoint(session, 1, dict(record(), data="modified"), key))
    with pytest.raises(AnchorError, match="size"):
        store.accept(checkpoint(session, 1, record("x" * 65536), key))
    with pytest.raises(AnchorError):
        decode(b'{"version":1,"version":2}')
    with pytest.raises(AnchorError):
        decode(b'{"x":NaN}')


def test_budget_exhaustion_fails_closed(tmp_path):
    store, _, session, key = setup_store(tmp_path, max_bytes=1)
    with pytest.raises(AnchorError, match="budget"):
        store.accept(checkpoint(session, 1, record(), key))


def test_lost_ack_keeps_evidence_and_retry_does_not_duplicate(tmp_path):
    store, _, session, key = setup_store(tmp_path)
    class Upstream:
        identity = AnchorIdentity(session, key)
        attempts = 0
        def submit(self, sequence, data):
            self.attempts += 1
            if self.attempts == 1:
                raise TimeoutError("remote acknowledgement lost")
    upstream = Upstream()
    relay = HostAnchorRelay(store, upstream, session)
    message = checkpoint(session, 1, record(), key)
    with pytest.raises(TimeoutError):
        relay.handle(canonical(message))
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 1
    ack = decode(relay.handle(canonical(message)))
    AnchorIdentity(session, key).check_ack(ack, 1, message["head_hash"])
    with pytest.raises(AnchorError, match="foreign"):
        relay.handle(canonical(dict(message, session="0" * 64)))


def test_ack_cannot_cross_session_sequence_or_direction(tmp_path):
    store, _, session, key = setup_store(tmp_path)
    message = checkpoint(session, 1, record(), key)
    ack = store.accept(message)
    identity = AnchorIdentity(session, key)
    with pytest.raises(AnchorError):
        identity.check_ack(ack, 2, message["head_hash"])
    with pytest.raises(AnchorError):
        identity.check_ack(message, 1, message["head_hash"])
    with pytest.raises(AnchorError):
        identity.check_ack(dict(ack, session="1" * 64), 1, message["head_hash"])


def test_ledger_blocks_after_missing_ack_and_explicit_recovery(tmp_path):
    store, _, session, key = setup_store(tmp_path)
    class Transport:
        identity = AnchorIdentity(session, key)
        fail = False
        def submit(self, sequence, data):
            ack = store.accept(checkpoint(session, sequence, data, key))
            if self.fail:
                raise TimeoutError("acknowledgement lost after durable acceptance")
            return ack
    transport = Transport()
    ledger = AuditLedger(tmp_path / "ledger.jsonl", transport=transport)
    ledger.append_event("open", {"session": session})
    transport.fail = True
    with pytest.raises(AuditIntegrityError):
        ledger.append_event("attempt", {"argv": ["/usr/bin/true"]})
    assert not ledger.verify().valid
    with pytest.raises(AuditIntegrityError, match="invalid ledger"):
        ledger.append_event("must-not-run", {})
    transport.fail = False
    ledger.reconcile_remote()
    assert ledger.verify().valid
    assert ledger.verify().records == 2
    assert len(ledger.path.read_text().splitlines()) == 2


def test_legacy_url_ledger_cannot_satisfy_production(tmp_path):
    ledger = AuditLedger(tmp_path / "ledger", remote_anchor_url="https://example.invalid/anchor", remote_anchor_key="test")
    assert ledger.production_anchor_ready is False


def test_local_ledger_budget_preserves_previous_head(tmp_path):
    ledger = AuditLedger(tmp_path / "ledger", max_ledger_bytes=500)
    ledger.append_event("one", {})
    before = ledger.path.read_bytes()
    with pytest.raises(AuditIntegrityError, match="budget"):
        ledger.append_event("large", {"value": "x" * 500})
    assert ledger.path.read_bytes() == before
    assert ledger.verify().valid


def test_oversize_transport_record_rejected_before_local_append(tmp_path):
    identity = AnchorIdentity("a" * 64, b"k" * 32)
    transport = HTTPSAnchorTransport("https://example.invalid/v1/checkpoints", identity)
    ledger = AuditLedger(tmp_path / "ledger", transport=transport)
    with pytest.raises(AuditIntegrityError, match="framing"):
        ledger.append_event("too-large", {"data": "x" * 65536})
    assert not ledger.path.exists()
    assert ledger.verify().valid


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl required for local TLS fixture")
def test_real_local_tls_acceptance_and_unavailable_service(tmp_path):
    store, _, session, key = setup_store(tmp_path)
    cert, tls_key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                    "-keyout", str(tls_key), "-out", str(cert)], check=True, capture_output=True, timeout=15)
    server = make_server(store, ("127.0.0.1", 0))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, tls_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    transport = HTTPSAnchorTransport(f"https://localhost:{server.server_port}/v1/checkpoints",
                                    AnchorIdentity(session, key), test_ca=cert, timeout=1)
    try:
        assert transport.production_ready is False
        ack = transport.submit(1, record())
        assert ack["accepted"] is True
        assert transport.submit(1, record()) == ack
        with store.connect() as db:
            stored = decode(db.execute("SELECT frame FROM checkpoints").fetchone()[0])
        assert "record" not in stored
        assert "data" not in stored
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    with pytest.raises(OSError):
        transport.submit(2, record("next", record()["record_hash"]))
