"""USB transport simulations, not physical presence or signing evidence."""
from collections import deque
import ctypes
import json

import pytest

from bulldog.hardware_approval import diagnostic


def packet(*, nonce=bytes(32), pending=False, decision=0, authority=0):
    data = bytearray(64)
    data[:11] = b"BULL-DIAG-3"
    data[11] = authority
    data[23] = pending
    data[24] = decision
    data[32:] = nonce
    return bytes(data)


class Function:
    """A fake C function accepting ctypes signature declarations."""
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class HID:
    def __init__(self, replies=(), decision=2, wrong_challenge=False):
        self.replies = deque(replies)
        self.decision = decision
        self.wrong_challenge = wrong_challenge
        self.nonce = None
        self.commands = []
        self.closed = False
        self.hid_init = Function(lambda: 0)
        self.hid_exit = Function(lambda: 0)
        self.hid_open = Function(lambda *args: 1)
        self.hid_error = Function(lambda *args: "test USB error")
        self.hid_write = Function(self.write)
        self.hid_read_timeout = Function(self.read)
        self.hid_close = Function(self.close)

    def write(self, handle, buffer, size):
        command = ctypes.string_at(buffer, size)[1:]
        self.commands.append(command[0])
        if command[0] == 2:
            self.nonce = command[1:33]
        elif command[0] == 3:
            self.nonce = None
            # The firmware emits this reply even when the host closes next.
            self.replies.append(packet())
        elif command[0] == 1:
            nonce = b"x" * 32 if self.wrong_challenge else self.nonce
            self.replies.append(packet(nonce=nonce or bytes(32),
                                       decision=self.decision if self.nonce else 0))
        return size

    def read(self, handle, buffer, size, timeout):
        if not self.replies:
            return 0
        data = self.replies.popleft()
        ctypes.memmove(buffer, data, min(len(data), size))
        return len(data)

    def close(self, handle):
        self.closed = True


@pytest.mark.parametrize("decision,expected", [(1, "NO"), (2, "YES")])
def test_stale_decisions_are_discarded_before_fresh_challenge(monkeypatch, capsys, decision, expected):
    old = b"o" * 32
    hid = HID([packet(), packet(nonce=old, decision=2)], decision=decision)
    monkeypatch.setattr(diagnostic.C, "CDLL", lambda name: hid)
    diagnostic.main(["--test-clicks"])
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["diagnostic_decision"] == expected
    assert result["challenge"] != old.hex()
    assert result["approval_available"] is False
    assert hid.commands == [1, 2, 1, 3]
    assert hid.closed
    # A second invocation drains the CANCEL response from the first test.
    diagnostic.main(["--test-clicks"])
    second = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert second["diagnostic_decision"] == expected
    assert second["challenge"] != result["challenge"]


def test_active_challenge_mismatch_still_cancels(monkeypatch):
    hid = HID([packet()], wrong_challenge=True)
    monkeypatch.setattr(diagnostic.C, "CDLL", lambda name: hid)
    with pytest.raises(SystemExit, match="challenge changed"):
        diagnostic.main(["--test-clicks"])
    assert hid.commands[-1] == 3
    assert hid.closed


@pytest.mark.parametrize("reply", [b"", b"bad", bytes(65), packet(authority=1)])
def test_bad_queued_report_never_arms(monkeypatch, reply):
    # A zero-length receive denotes an empty queue, so use a negative result
    # for that transport-failure case rather than a valid queue terminator.
    hid = HID([reply])
    if not reply:
        hid.hid_read_timeout = Function(lambda *args: -1)
    monkeypatch.setattr(diagnostic.C, "CDLL", lambda name: hid)
    with pytest.raises(SystemExit):
        diagnostic.main(["--test-clicks"])
    assert hid.commands == []
    assert hid.closed


def test_receive_queue_is_bounded(monkeypatch):
    hid = HID([packet()] * 8)
    monkeypatch.setattr(diagnostic.C, "CDLL", lambda name: hid)
    with pytest.raises(SystemExit, match="did not settle"):
        diagnostic.main(["--test-clicks"])
    assert hid.commands == []
    assert hid.closed
