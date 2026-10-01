"""Wire limits and optional real IPC; skips never qualify a deployment."""

import json
import os
import socket
import threading
from types import SimpleNamespace

import pytest

from bulldog.gateway_transport import GatewayServer
from bulldog.gateway_wire import GatewayDenied, read_frame


class Fragments:
    def __init__(self, *chunks):
        self.chunks = iter(chunks)

    def settimeout(self, timeout):
        assert timeout > 0

    def recv(self, maximum):
        chunk = next(self.chunks, b"")
        assert len(chunk) <= maximum
        return chunk


def test_frame_handles_split_request_without_changing_semantics():
    assert read_frame(Fragments(b'{"method":', b'"list"}\n'), limit=100, timeout=1) == {
        "method": "list"
    }


@pytest.mark.parametrize("data", [b'{"method":"list"}', b"{}\n{}\n", b"[]\n", b"no\n"])
def test_incomplete_stacked_and_non_object_frames_rejected(data):
    with pytest.raises(GatewayDenied):
        read_frame(Fragments(data), limit=100, timeout=1)


def test_real_server_rejects_wrong_kernel_uid_before_reading(tmp_path):
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as exc:
        pytest.skip(f"live Unix IPC unavailable: {exc}; not a transport PASS")
    directory = tmp_path / "endpoint"
    directory.mkdir(mode=0o700)
    calls = []
    authority = SimpleNamespace(
        config={"agent_uid": os.geteuid() + 1},
        handle=lambda *a, **k: calls.append((a, k)),
    )
    server = GatewayServer(authority, directory / "agent.sock", agent_gid=os.getegid())
    thread = threading.Thread(target=server.serve)
    thread.start()
    try:
        client.settimeout(2)
        client.connect(str(directory / "agent.sock"))
        assert client.recv(1) == b""
        assert calls == []
    finally:
        client.close()
        server.close()
        thread.join(timeout=3)
