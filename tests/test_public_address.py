"""Every egress path shares one definition of a public destination."""

import socket

import pytest

from bulldog.egress_proxy import EgressBroker, EgressDenied
from bulldog.pinned_egress import resolve_public_once
from bulldog.public_address import is_public

INTERNAL = [
    "100.100.100.200",  # Shared address space; a cloud metadata service.
    "100.64.0.1",
    "10.0.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "192.0.0.8",
    "198.18.0.1",
    "0.0.0.0",
    "224.0.0.1",
    "::1",
    "fd00::1",
    "fe80::1",
    "::ffff:10.0.0.1",
    "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1.
    "2002:a00:1::1",  # 6to4 wrapping 10.0.0.1.
]


@pytest.mark.parametrize("address", INTERNAL)
def test_internal_addresses_are_not_public(address):
    assert is_public(address) is False


@pytest.mark.parametrize("address", ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
                                     "64:ff9b::5db8:d70e"])
def test_public_addresses_are_public(address):
    assert is_public(address) is True


def answer(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (address, 443))],
    )


@pytest.mark.parametrize("address", ["100.100.100.200", "64:ff9b::a00:1", "2002:a00:1::1"])
def test_brokers_refuse_internal_answers(monkeypatch, address):
    answer(monkeypatch, address)
    with pytest.raises(EgressDenied):
        EgressBroker._resolve_public_addresses("api.example.com", 443)
    with pytest.raises(EgressDenied):
        resolve_public_once("api.example.com", 443)
