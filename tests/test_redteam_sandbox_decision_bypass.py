"""Red-team probe: Decision.SANDBOX must not pass the legacy broker gate.

The deterministic policy returns Decision.SANDBOX for actions scored in
the 0.55-0.84 risk band. In the runtime execution path that verdict
means "run inside the namespace sandbox". The legacy broker paths have
no sandbox step, so a SANDBOX verdict must be treated as a denial there.
This probe fails if a mid-risk verdict silently becomes an approved
broker operation.
"""

from types import SimpleNamespace

import pytest

import bulldog.dispatcher as dispatcher_module
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import CapabilityDispatcher, DispatchRequest
from bulldog.models import Capability, Decision, Evaluation, Provenance


class MidRiskSandboxEngine:
    """Returns the SANDBOX verdict the policy produces for mid-risk actions."""

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


def test_redteam_sandbox_verdict_must_not_pass_egress_broker():
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

    dispatcher.fetch_egress(
        url="https://example.com/",
        method="GET",
        request=egress_request(),
    )

    if broker.calls:
        pytest.fail(
            "BYPASS CONFIRMED: Decision.SANDBOX passed the legacy broker "
            "authorization gate; a mid-risk fetch executed on the host "
            "without sandbox mediation: " + repr(broker.calls)
        )


def test_redteam_sandbox_verdict_must_not_reach_secret_broker(monkeypatch, tmp_path):
    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    def fake_request_secret(**kwargs):
        pytest.fail(
            "BYPASS CONFIRMED: Decision.SANDBOX passed the legacy broker "
            "authorization gate; a mid-risk credential was released."
        )

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        fake_request_secret,
    )

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=MidRiskSandboxEngine()),
        secret_broker=FakeSecretBroker(),
    )

    dispatcher.get_secret(
        token="grant-token",
        name="API_KEY",
        request=secret_request(),
    )
