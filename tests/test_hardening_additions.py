"""Regression tests for the hardening additions commit."""

from __future__ import annotations

import os
import socket
import stat

import pytest

from bulldog.agent_sentinel import AgentSentinel
from bulldog.container_hardening import (
    audit_launcher_script,
    assert_no_shared_mounts,
    effective_capabilities,
    parse_mountinfo,
)
from bulldog.socket_hardening import (
    HardeningError,
    accept_authenticated,
    bind_private_unix_socket,
    peer_credentials,
)

posix = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX")


@posix
def test_bind_private_unix_socket_mode_and_dir(tmp_path):
    srv = bind_private_unix_socket(tmp_path / "sock" / "broker.sock")
    try:
        assert stat.S_IMODE(os.lstat(srv.getsockname()).st_mode) & 0o077 == 0
        assert stat.S_IMODE(os.lstat(tmp_path / "sock").st_mode) == 0o700
    finally:
        srv.close()


@posix
def test_bind_refuses_preplanted_symlink(tmp_path):
    target = tmp_path / "victim"
    target.write_text("x")
    link = tmp_path / "sock"
    os.symlink(target, link)
    with pytest.raises(HardeningError):
        bind_private_unix_socket(link)


@posix
def test_peer_credentials_matches_euid():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _pid, uid, _gid = peer_credentials(b)
        assert uid == os.geteuid()
    finally:
        a.close()
        b.close()


@posix
def test_accept_authenticated_rejects_foreign_uid(tmp_path):
    srv = bind_private_unix_socket(tmp_path / "s.sock")
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(tmp_path / "s.sock"))
        try:
            with pytest.raises(HardeningError):
                accept_authenticated(srv, expected_uid=os.geteuid() + 1)
        finally:
            client.close()
    finally:
        srv.close()


MOUNTINFO_SHARED = (
    "23 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
    "24 23 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
)
MOUNTINFO_PRIVATE = (
    "23 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
    "24 23 0:5 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
)


def test_mountinfo_flags_shared_root():
    entries = parse_mountinfo(MOUNTINFO_SHARED)
    assert any(e.shared and e.mount_point == "/" for e in entries)
    with pytest.raises(HardeningError):
        assert_no_shared_mounts(MOUNTINFO_SHARED)
    assert_no_shared_mounts(MOUNTINFO_PRIVATE)  # must not raise


def test_effective_capabilities_parsing():
    assert effective_capabilities("CapEff:\t0000000000000000\n") == 0
    assert effective_capabilities("CapEff:\t00000000a80425fb\n") != 0


def test_launcher_audit_flags_missing_and_unquoted():
    findings = audit_launcher_script("#!/bin/sh\nmount --bind $PROJECT $ROOTFS/workspace\n")
    assert any("set -euo pipefail" in f for f in findings)
    assert any("unquoted" in f for f in findings)

    good = (
        "#!/bin/sh\nset -euo pipefail\n"
        "unshare --mount --propagation private /bin/true\n"
        "mount --make-rprivate /\n"
        'mount -t tmpfs -o nosuid,nodev,noexec tmpfs "$ROOTFS/tmp"\n'
        'mount --bind "$PROJECT" "$ROOTFS/workspace"\n'
    )
    assert audit_launcher_script(good) == []


def test_sentinel_env_marker_raises_verdict():
    clean = AgentSentinel(env={"PATH": "/usr/bin"})
    dirty = AgentSentinel(env={"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "redacted"})
    assert dirty.env_score()
    assert not clean.env_score()
    assert dirty.evaluate().score > clean.evaluate().score


def test_sentinel_verdict_monotonic_in_signals():
    weak = AgentSentinel(env={"MCP_TOKEN": "x"})
    strong = AgentSentinel(env={"MCP_TOKEN": "x", "CLAUDECODE": "1", "OPENAI_API_KEY": "y"})
    assert strong.evaluate().score >= weak.evaluate().score


def test_sentinel_burst_cadence_flags_machine_input():
    sentinel = AgentSentinel(env={})
    base = 1000.0
    for i in range(20):
        sentinel.record_input_event(base + i * 0.001)  # 1ms apart: injected
    assert "cadence:burst_injection" in sentinel.cadence_score()

    human = AgentSentinel(env={})
    for i in range(20):
        human.record_input_event(base + i * 0.4)  # 400ms apart: typed
    assert human.cadence_score() == {}


def test_sentinel_on_verdict_fires_on_agent(tmp_path):
    seen = []
    sentinel = AgentSentinel(
        env={"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "y", "CLAUDECODE": "1"},
        on_verdict=seen.append,
    )
    report = sentinel.evaluate()
    assert report.verdict == "agent"
    assert seen and seen[0].verdict == "agent"


def test_unshare_invocation_includes_ipc_namespace():
    import inspect
    from pathlib import Path
    from bulldog import namespace_sandbox
    src = Path(inspect.getsourcefile(namespace_sandbox)).read_text()
    assert '"--ipc",' in src
    assert src.index('"--ipc",') < src.index("str(self.launcher),")
