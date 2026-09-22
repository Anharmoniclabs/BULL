import json
import os
import socket
import time

import pytest

from bulldog.anchor_service import AnchorError, authenticate
from bulldog.guest_engine import load_authority
from bulldog.microvm import MicroVMError, validate_channels
from bulldog.audit_transport import production_transport_from_environment


def authority(tmp_path, **changes):
    deployment = tmp_path / 'deployment'
    deployment.mkdir()
    data = {'session': 'a' * 64, 'control_key': 'b' * 64, 'audit_master': 'c' * 64,
            'request': {'argv': ['/usr/bin/true'], 'capabilities': ['process.exec'], 'timeout': 5},
            'environment': {}, 'expires': int(time.time()) + 60}
    data.update(changes)
    signed = authenticate(data, bytes.fromhex(data['control_key']), purpose='guest-deployment')
    path = deployment / 'session.json'
    path.write_text(json.dumps(signed))
    path.chmod(0o600)
    return path


def test_authority_rejects_tampering_and_expiry(tmp_path):
    path = authority(tmp_path)
    assert load_authority(tmp_path)['request']['argv'] == ['/usr/bin/true']
    data = json.loads(path.read_text())
    data['request']['argv'].append('unexpected')
    path.write_text(json.dumps(data))
    with pytest.raises(AnchorError):
        load_authority(tmp_path)


def test_expired_authority_is_not_admitted(tmp_path):
    authority(tmp_path, expires=int(time.time()) - 1)
    with pytest.raises(AnchorError, match='expired'):
        load_authority(tmp_path)


@pytest.mark.parametrize('mode', [0o620, 0o602, 0o666])
def test_authority_rejects_writable_permissions(tmp_path, mode):
    path = authority(tmp_path)
    assert load_authority(tmp_path)['request']['argv'] == ['/usr/bin/true']
    path.chmod(mode)
    with pytest.raises(AnchorError, match='invalid session authority file'):
        load_authority(tmp_path)


def test_relay_environment_alone_cannot_satisfy_gate(monkeypatch):
    monkeypatch.setenv('BULL_AUDIT_TRANSPORT', 'relay')
    monkeypatch.setenv('BULL_AUDIT_SESSION_ID', 'a' * 64)
    with pytest.raises(AnchorError, match='bootstrap'):
        production_transport_from_environment()


def test_private_paired_channels(tmp_path):
    tmp_path.chmod(0o700)
    with socket.socket(socket.AF_UNIX) as control, socket.socket(socket.AF_UNIX) as audit:
        control.bind(str(tmp_path / 'control'))
        audit.bind(str(tmp_path / 'audit'))
        for path in (tmp_path / 'control', tmp_path / 'audit'):
            path.chmod(0o600)
        values = {'CONTROL_SOCKET': str(tmp_path / 'control'), 'AUDIT_SOCKET': str(tmp_path / 'audit')}
        validate_channels(values)
        (tmp_path / 'audit').chmod(0o666)
        with pytest.raises(MicroVMError, match='private'):
            validate_channels(values)
        with pytest.raises(MicroVMError, match='paired'):
            validate_channels(dict(values, AUDIT_SOCKET=''))
