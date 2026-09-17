from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import struct
from types import SimpleNamespace

import pytest

from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied, DispatchRequest
from bulldog.egress_proxy import EgressBroker, EgressDenied
from bulldog.engine import BulldogEngine
from bulldog.models import Capability, Provenance
from bulldog.secret_broker import SecretBroker, SecretBrokerError


class _PeerSocket:
    def __init__(self, *, pid=1, uid=1000, gid=1000):
        self.payload = struct.pack("3i", pid, uid, gid)

    def getsockopt(self, level, option, size):
        return self.payload


def test_secret_broker_rejects_wrong_unix_peer_uid(tmp_path):
    broker = SecretBroker(
        tmp_path / "secret.sock",
        require_peer_credentials=True,
        allowed_peer_uids={1234},
    )
    assert broker._authorize_peer(_PeerSocket(uid=1234))[1] == 1234
    with pytest.raises(SecretBrokerError, match="UID"):
        broker._authorize_peer(_PeerSocket(uid=9999))


def test_egress_broker_rejects_wrong_unix_peer_uid(tmp_path):
    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={"example.com"},
        require_peer_credentials=True,
        allowed_peer_uids={1234},
    )
    assert broker._authorize_peer(_PeerSocket(uid=1234))[1] == 1234
    with pytest.raises(EgressDenied, match="UID"):
        broker._authorize_peer(_PeerSocket(uid=9999))


def test_one_shot_secret_grant_is_race_safe(tmp_path):
    broker = SecretBroker(tmp_path / "secret.sock")
    broker.put_secret("TOKEN", "VALUE")
    grant = broker.issue_grant(
        allowed_names={"TOKEN"},
        sandbox_id="domain-A",
        max_uses=1,
    )

    def attempt(_):
        try:
            return broker._authorize_and_get(
                grant.token,
                "TOKEN",
                sandbox_id="domain-A",
            )
        except SecretBrokerError:
            return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(32)))
    assert results.count("VALUE") == 1
    assert results.count(None) == 31


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::",
        "ff02::1",
        "::ffff:127.0.0.1",
    ],
)
def test_nonpublic_and_metadata_class_addresses_fail_closed(address, monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, 443, 0, 0) if ":" in address else (address, 443),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(EgressDenied, match="non-public"):
        EgressBroker._resolve_public_addresses("example.com", 443)


def test_mixed_public_private_dns_answers_fail_closed(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(EgressDenied):
        EgressBroker._resolve_public_addresses("example.com", 443)


def test_get_authorization_cannot_be_repurposed_as_post():
    class FakeBroker:
        def fetch(self, *, method, url):
            pytest.fail("egress broker must not be reached")

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=BulldogEngine()),
        egress_broker=FakeBroker(),
    )
    request = DispatchRequest(
        proposal={
            "task": "read public page",
            "operation": "fetch",
            "resource": "https://example.com/",
        },
        trusted=TrustedExecutionContext(
            actor="host",
            provenance=(Provenance.HUMAN,),
            security_context_id="ctx",
        ),
        granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
    )

    with pytest.raises(DispatchDenied, match="capability mismatch"):
        dispatcher.fetch_egress(
            url="https://example.com/",
            method="POST",
            request=request,
        )


def test_sandbox_bootstrap_scrubs_environment_and_omits_host_surfaces():
    import bulldog.namespace_sandbox as namespace_module

    launcher = Path(namespace_module.__file__).with_name("_namespace_launcher.sh")
    text = launcher.read_text(encoding="utf-8")
    for key in (
        "PYTHONPATH",
        "PYTHONHOME",
        "LD_PRELOAD",
        "BASH_ENV",
        "GIT_CONFIG_GLOBAL",
        "SSH_AUTH_SOCK",
        "DOCKER_HOST",
    ):
        assert key in text
    assert 'HOME"] = "/nonexistent"' in text
    assert "mount -t proc" not in text
    assert '"$ROOTFS/sys"' not in text
    assert "/run/user" in text  # appears only in the explicit absence comment


def test_redirects_are_not_followed_without_reauthorization(tmp_path, monkeypatch):
    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={"example.com"},
    )
    monkeypatch.setattr(
        EgressBroker,
        "_resolve_public_addresses",
        staticmethod(lambda host, port: ("93.184.216.34",)),
    )

    class RedirectResponse:
        status = 302

        def read(self, n):
            return b""

        def getheaders(self):
            return [("Location", "https://other.example/")]

    class FakeConnection:
        def __init__(self, **kwargs):
            pass

        def request(self, method, path, headers):
            pass

        def getresponse(self):
            return RedirectResponse()

        def close(self):
            pass

    import bulldog.egress_proxy as egress_module

    monkeypatch.setattr(egress_module, "_PinnedHTTPSConnection", FakeConnection)
    with pytest.raises(EgressDenied, match="redirect"):
        broker.fetch(method="GET", url="https://example.com/")
