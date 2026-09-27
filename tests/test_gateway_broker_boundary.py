"""Real production broker policy methods; only external HTTP is a fixture."""

from dataclasses import replace
import os
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from bulldog.audit import AuditLedger
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import DispatchDenied, DispatchRequest
from bulldog.egress_proxy import EgressBroker, EgressClient, EgressResponse
from bulldog.models import Capability, Decision, Evaluation, Provenance
from bulldog.profiles import _verify_broker_boundary
from bulldog.production_router import ProductionEffect, ProductionEffectRouter
from bulldog.security_domain import SecurityDomainRegistry
from test_human_approval import SyntheticSK, dispatcher_fixture


@pytest.fixture
def production_broker(tmp_path):
    approval = tmp_path / "approval"
    approval.mkdir(mode=0o700)
    key = SyntheticSK()
    state = SimpleNamespace(
        root=tmp_path,
        ledger=AuditLedger(tmp_path / "audit.jsonl"),
        config={
            "state_directory": str(approval),
            "credentials": {"operator": key.public},
            "routine_egress_urls": ["https://example.com/manual"],
            "ttl_seconds": 300,
        },
    )
    dispatcher, _, _, _ = dispatcher_fixture(state)
    registry = SecurityDomainRegistry(ledger=state.ledger)
    domain = registry.create_root(
        actor="host",
        initial_prompt="fixed public reference",
        capability_ceiling={Capability.NETWORK_OUTBOUND},
        egress_hosts={"example.com"},
    )
    dispatcher.domain_registry = registry
    effects = []

    def fetch(*, method, url):
        effects.append((method, url))
        return EgressResponse(200, {}, b"safe fixture")

    dispatcher.egress_broker = SimpleNamespace(fetch=fetch)
    request = DispatchRequest(
        {"operation": "fetch", "resource": "https://example.com/manual"},
        registry.trusted_context(domain.domain_id),
        frozenset({Capability.NETWORK_OUTBOUND}),
        domain_id=domain.domain_id,
    )
    return dispatcher, registry, request, effects


def test_real_production_broker_accepts_exact_signed_routine_authority(
    production_broker,
):
    dispatcher, _, request, effects = production_broker
    result = ProductionEffectRouter(dispatcher).dispatch(
        ProductionEffect(
            "network.request",
            request,
            {"url": "https://example.com/manual", "method": "GET"},
        )
    )
    assert result.body == b"safe fixture"
    assert effects == [("GET", "https://example.com/manual")]


@pytest.mark.parametrize(
    "verdict", [Decision.SANDBOX, Decision.DENY, Decision.ESCALATE]
)
def test_non_allow_never_reaches_production_egress(production_broker, verdict):
    dispatcher, _, request, effects = production_broker
    dispatcher.broker_engine.evaluate = lambda _: Evaluation(
        verdict, 0.8, ("fixture verdict",)
    )
    with pytest.raises(DispatchDenied, match="explicit ALLOW"):
        ProductionEffectRouter(dispatcher).dispatch(
            ProductionEffect(
                "network.request",
                request,
                {"url": "https://example.com/manual", "method": "GET"},
            )
        )
    assert effects == []


def test_domain_mismatch_is_rejected_before_any_broker_effect(production_broker):
    dispatcher, _, request, effects = production_broker
    with pytest.raises(DispatchDenied, match="domain"):
        dispatcher.fetch_egress(
            url="https://example.com/manual", domain_id="sibling", request=request
        )
    assert effects == []


def test_frozen_domain_cannot_use_cached_menu(production_broker):
    dispatcher, registry, request, effects = production_broker
    registry.freeze(request.domain_id, "revoked")
    with pytest.raises(DispatchDenied):
        ProductionEffectRouter(dispatcher).dispatch(
            ProductionEffect(
                "network.request",
                request,
                {"url": "https://example.com/manual", "method": "GET"},
            )
        )
    assert effects == []


def test_destination_allowlist_does_not_replace_capability_ceiling(production_broker):
    dispatcher, registry, request, effects = production_broker
    domain = registry.create_root(
        actor="no-network",
        initial_prompt="read only",
        capability_ceiling={Capability.FS_READ_PROJECT},
        egress_hosts={"example.com"},
    )
    request = replace(request, domain_id=domain.domain_id)
    with pytest.raises(DispatchDenied):
        ProductionEffectRouter(dispatcher).dispatch(
            ProductionEffect(
                "network.request",
                request,
                {"url": "https://example.com/manual", "method": "GET"},
            )
        )
    assert effects == []


def test_in_process_broker_cannot_claim_production_peer_auth(tmp_path):
    broker = EgressBroker(
        tmp_path / "broker.sock",
        allowed_hosts={"example.com"},
        require_peer_credentials=True,
    )
    with pytest.raises(DispatchDenied, match="EgressClient"):
        _verify_broker_boundary("egress", broker)


def _unix_or_skip():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.close()
    except OSError as exc:
        pytest.skip(f"live Unix IPC unavailable: {exc}; not a transport PASS")


def test_real_broker_socket_and_large_response(tmp_path):
    _unix_or_skip()
    root = tmp_path / "broker"
    root.mkdir(mode=0o700)
    broker = EgressBroker(
        root / "egress.sock",
        allowed_hosts={"example.com"},
        require_peer_credentials=True,
    )
    effects = []

    def fetch(*, method, url):
        effects.append((method, url))
        return EgressResponse(200, {}, b"x" * 65536)

    broker.fetch = fetch  # Final HTTP only; actual peer credentials + Unix framing.
    broker.start()
    try:
        response = EgressClient(broker.socket_path, os.geteuid()).fetch(
            method="GET", url="https://example.com/"
        )
        assert len(response.body) == 65536
        assert effects == [("GET", "https://example.com/")]
        with pytest.raises(Exception, match="peer uid"):
            EgressClient(broker.socket_path, os.geteuid() + 1).fetch(
                method="GET", url="https://example.com/"
            )
        assert len(effects) == 1
    finally:
        broker.stop()
