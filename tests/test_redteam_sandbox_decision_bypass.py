"""Regression: Decision.SANDBOX must not pass the legacy broker gate."""

from types import SimpleNamespace

import pytest

import bulldog.dispatcher as dispatcher_module
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import (
    CapabilityDispatcher,
    DispatchDenied,
    DispatchRequest,
)
from bulldog.models import Capability, Decision, Evaluation, Provenance


class MidRiskSandboxEngine:
    def evaluate(self, action):
        return Evaluation(
            decision=Decision.SANDBOX,
            risk=0.6,
            reasons=("mid-risk action routed to sandbox",),
        )


def trusted_context():
    return TrustedExecutionContext(
        actor="trusted-host-agent",
        provenance=(Provenance.HUMAN,),
        security_context_id="ctx-sandbox-gap",
    )


def egress_request():
    return DispatchRequest(
        proposal={
            "task": "fetch moderately risky URL",
            "operation": "fetch",
            "resource": "https://example.com/",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
    )


def secret_request():
    return DispatchRequest(
        proposal={
            "task": "retrieve mid-risk credential",
            "operation": "secret.get",
            "resource": "API_KEY",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
    )


def test_redteam_sandbox_verdict_cannot_pass_egress_broker():
    class FakeEgressBroker:
        def __init__(self):
            self.calls = []

        def fetch(self, *, method, url):
            self.calls.append((method, url))
            return SimpleNamespace(status=200, headers={}, body=b"ok")

    broker = FakeEgressBroker()
    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=MidRiskSandboxEngine()),
        egress_broker=broker,
    )

    with pytest.raises(DispatchDenied, match="explicit ALLOW"):
        dispatcher.fetch_egress(
            url="https://example.com/",
            method="GET",
            request=egress_request(),
        )

    assert broker.calls == []


def test_redteam_sandbox_verdict_cannot_reach_secret_broker(
    monkeypatch, tmp_path
):
    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    calls = []

    def fake_request_secret(**kwargs):
        calls.append(dict(kwargs))
        return "should-not-be-released"

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        fake_request_secret,
    )

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=MidRiskSandboxEngine()),
        secret_broker=FakeSecretBroker(),
    )

    with pytest.raises(DispatchDenied, match="explicit ALLOW"):
        dispatcher.get_secret(
            token="grant-token",
            name="API_KEY",
            request=secret_request(),
        )

    assert calls == []
