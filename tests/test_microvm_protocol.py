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


def test_missing_and_oversize_completion_are_failures(channels):
    host, _, _, b = channels
    with pytest.raises(AnchorError, match='deadline'):
        host.receive('result')
    b.sendall((65537).to_bytes(4, 'big'))
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
