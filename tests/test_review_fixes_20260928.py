"""Regressions for the automated review of Anharmoniclabs/BULL#89."""

import os
from pathlib import Path
import re
import socket
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

from bulldog.control_plane import ControlPlane
from bulldog.egress_gateway import EgressGateway, EgressPolicy, GatewayConfig, _DnsProtocol

ROOT = Path(__file__).resolve().parents[1]


class Transport:
    def __init__(self):
        self.sent = []
        self.event = threading.Event()

    def sendto(self, data, addr):
        self.sent.append(data)
        self.event.set()


def query(name=b"api", zone=b"example", tld=b"com"):
    labels = b"".join(bytes([len(x)]) + x for x in (name, zone, tld))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


def dns_protocol(upstream):
    gateway = EgressGateway(
        EgressPolicy({"api.example.com": {}}), GatewayConfig(dns_upstream=upstream)
    )
    protocol = _DnsProtocol(gateway)
    protocol.connection_made(Transport())
    return protocol


def test_ipv6_dns_upstream_is_answered():
    try:
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        server.bind(("::1", 0))
    except OSError as exc:
        pytest.skip(f"IPv6 loopback unavailable: {exc}")
    server.settimeout(5)

    def answer():
        data, peer = server.recvfrom(512)
        server.sendto(b"ANSWER" + data[:2], peer)

    threading.Thread(target=answer, daemon=True).start()
    protocol = dns_protocol(("::1", server.getsockname()[1]))
    protocol.datagram_received(query(), ("127.0.0.1", 5353))
    assert protocol.transport.event.wait(5)
    assert protocol.transport.sent[0].startswith(b"ANSWER")
    server.close()


def test_unreachable_upstream_is_refused_not_silent():
    families = []

    def unavailable(family, kind):
        families.append(family)
        raise OSError("address family unavailable")

    protocol = dns_protocol(("::1", 9))
    with patch("bulldog.egress_gateway.socket.socket", side_effect=unavailable):
        protocol.datagram_received(query(), ("127.0.0.1", 5353))
    assert families == [socket.AF_INET6]  # IPv6 upstream gets an IPv6 socket.
    assert len(protocol.transport.sent) == 1
    assert protocol.transport.sent[0][3] & 0x0F == 5  # RCODE REFUSED
    assert protocol._slots.acquire(blocking=False)  # The slot was returned.


def test_dns_forwards_in_flight_are_bounded():
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))  # Never answers: every forward waits 2 s.
    protocol = dns_protocol(("127.0.0.1", silent.getsockname()[1]))
    protocol._slots = threading.BoundedSemaphore(2)
    for _ in range(5):
        protocol.datagram_received(query(), ("127.0.0.1", 5353))
    refused_now = [x for x in protocol.transport.sent if x[3] & 0x0F == 5]
    assert len(refused_now) == 3
    assert threading.active_count() < 50
    silent.close()


def test_revoke_all_kills_tokens_from_closed_epochs_in_grace():
    from bulldog.token_broker import BrokerError, TokenBroker

    broker = TokenBroker(grace_seconds=300)
    broker.store_upstream_secret("api.example.com", b"real-secret")
    old, _ = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
    revoked, jti = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
    broker.revoke(jti)
    broker.rotate()  # Old epoch closed but inside its 300 s grace window.
    broker.verify(old)
    broker.revoke_all()
    for token in (old, revoked):
        with pytest.raises(BrokerError):
            broker.verify(token)
        with pytest.raises(BrokerError):
            broker.exchange(token, "NETWORK_EGRESS", "api.example.com")
    fresh, _ = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
    broker.verify(fresh)


def test_console_without_audit_ledger_is_not_operational():
    with tempfile.TemporaryDirectory(prefix="bull-console-") as directory:
        proc = Path(directory) / "proc"
        proc.mkdir()
        with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
            control = ControlPlane(workspace=directory, auto_scan=False,
                                   dynamic_attestation=False, proc_root=proc)
            health = control.snapshot()["system_health"]
    assert health["operational"] is False


def test_installer_checks_policy_before_enabling_networking():
    script = (ROOT / "deploy" / "install_egress_gateway.sh").read_text()
    check = script.index("--check-policy")
    assert script.index("daemon-reload") < check
    for activation in re.finditer(r"systemctl (enable|start)", script):
        assert activation.start() > check
    assert "exit 0" in script[check:script.index("systemctl enable")]
