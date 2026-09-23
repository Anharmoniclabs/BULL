import socket
import pytest

from bulldog.anchor_service import AnchorError, authenticate, canonical
from bulldog.microvm_protocol import RemoteSessionError, SessionChannel


@pytest.fixture
def channels():
    a, b = socket.socketpair()
    try:
        yield (SessionChannel(a.fileno(), 'a' * 64, b'k' * 32, side='host', timeout=.1),
               SessionChannel(b.fileno(), 'a' * 64, b'k' * 32, side='guest', timeout=.1), a, b)
    finally:
        a.close()
        b.close()


def test_roundtrip_workload_text_is_only_payload(channels):
    host, guest, _, _ = channels
    host.send('execute', {'argv': ['/usr/bin/true']})
    assert guest.receive('execute')['argv'] == ['/usr/bin/true']
    guest.send('result', {'stdout': 'BULL_RESULT PASS\n', 'returncode': 7})
    assert host.receive('result')['returncode'] == 7


@pytest.mark.parametrize('change', [dict(session='b' * 64), dict(sequence=2), dict(sequence=True),
                                    dict(kind='result'), dict(extra='field')])
def test_authenticated_wrong_session_sequence_or_operation_rejected(channels, change):
    _, guest, a, _ = channels
    frame = authenticate(dict({'version': 1, 'session': 'a' * 64, 'sequence': 1,
                               'kind': 'execute', 'payload': {}}, **change), b'k' * 32,
                         purpose='control-host')
    raw = canonical(frame)
    a.sendall(len(raw).to_bytes(4, 'big') + raw)
    with pytest.raises(AnchorError):
        guest.receive('execute')


@pytest.mark.parametrize('length', [0, 65537])
def test_invalid_completion_length_fails_before_payload(channels, length):
    host, _, _, b = channels
    b.sendall(length.to_bytes(4, 'big'))
    with pytest.raises(AnchorError, match='length'):
        host.receive('result')


def test_replay_rejected(channels):
    _, guest, a, _ = channels
    raw = canonical(authenticate({'version': 1, 'session': 'a' * 64, 'sequence': 1,
                                  'kind': 'execute', 'payload': {}}, b'k' * 32, purpose='control-host'))
    a.sendall(len(raw).to_bytes(4, 'big') + raw)
    guest.receive('execute')
    a.sendall(len(raw).to_bytes(4, 'big') + raw)
    with pytest.raises(AnchorError):
        guest.receive('execute')


def test_authenticated_guest_error_cannot_be_a_completion(channels):
    host, guest, _, _ = channels
    guest.send('error', {'type': 'ProductionGateFailure', 'detail': 'required protection unavailable'})
    with pytest.raises(RemoteSessionError, match='required protection'):
        host.receive('result')


def test_fresh_sequence_cannot_reuse_execution_authority(channels):
    host, guest, a, _ = channels
    host.send('execute', {})
    guest.receive('execute')
    raw = canonical(authenticate({'version': 1, 'session': 'a' * 64,
        'sequence': 2, 'kind': 'execute', 'payload': {}}, b'k' * 32,
        purpose='control-host'))
    a.sendall(len(raw).to_bytes(4, 'big') + raw)
    with pytest.raises(AnchorError, match='one-shot'):
        guest.receive('execute')
    with pytest.raises(AnchorError, match='one-shot'):
        host.send('execute', {})


def test_timeout_prevents_late_result_reuse(channels):
    host, guest, _, _ = channels
    with pytest.raises(AnchorError, match='deadline'):
        host.receive('result')
    guest.send('result', {'returncode': 0})
    with pytest.raises(AnchorError, match='unusable'):
        host.receive('result')


def test_invalid_frame_prevents_following_valid_frame(channels):
    host, guest, a, _ = channels
    a.sendall((0).to_bytes(4, 'big'))
    with pytest.raises(AnchorError, match='length'):
        guest.receive('execute')
    host.send('execute', {})
    with pytest.raises(AnchorError, match='unusable'):
        guest.receive('execute')
