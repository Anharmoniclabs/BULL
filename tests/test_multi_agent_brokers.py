import json
from types import SimpleNamespace

import pytest

from bulldog.agent_isolation import AgentIsolationRegistry
from bulldog.audit import AuditLedger
from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.egress_proxy import EgressResponse
from bulldog.models import ActionRequest, Capability, Provenance
from bulldog.runtime import BulldogRuntime
from bulldog.secret_broker import SecretBroker, SecretBrokerError


def _register(
    registry,
    *,
    agent_id="agent",
    capabilities=frozenset({Capability.FS_READ_PROJECT}),
):
    return registry.register_agent(
        agent_id=agent_id,
        model_id="model-A",
        initial_intent="inspect repository",
        initial_command=["python", "agent.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=capabilities,
    )


def test_multi_agent_mode_disables_unscoped_secret_and_egress(tmp_path):
    registry = AgentIsolationRegistry()
    _register(registry)

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(),
        secret_broker=SimpleNamespace(socket_path=tmp_path / "secret.sock"),
        egress_broker=SimpleNamespace(fetch=lambda **kwargs: None),
        agent_registry=registry,
    )

    with pytest.raises(DispatchDenied):
        dispatcher.get_secret(token="x", name="TOKEN")

    with pytest.raises(DispatchDenied):
        dispatcher.fetch_egress(url="https://example.com")


def test_scoped_secret_uses_registry_sandbox_identity_and_audits(tmp_path):
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(ledger_path)
    registry = AgentIsolationRegistry(ledger=ledger)
    envelope = _register(registry)

    broker = SecretBroker(tmp_path / "secret.sock")
    broker.put_secret("TOKEN", "VALUE")
    grant = broker.issue_grant(
        allowed_names={"TOKEN"},
        sandbox_id=envelope.sandbox_id,
        max_uses=1,
    )
    broker.start()

    try:
        dispatcher = CapabilityDispatcher(
            runtime=SimpleNamespace(),
            secret_broker=broker,
            agent_registry=registry,
        )

        assert dispatcher.get_secret_for_agent(
            agent_id="agent",
            token=grant.token,
            name="TOKEN",
        ) == "VALUE"

        with pytest.raises(SecretBrokerError):
            dispatcher.get_secret_for_agent(
                agent_id="agent",
                token=grant.token,
                name="TOKEN",
            )
    finally:
        broker.stop()

    records = [
        json.loads(line)
        for line in ledger_path.read_text().splitlines()
    ]
    access = [
        record
        for record in records
        if record.get("event_type") == "agent_secret_access"
    ]
    assert [record["data"]["event"]["allowed"] for record in access] == [
        True,
        False,
    ]


class _FakeEgressBroker:
    def __init__(self):
        self.calls = []

    def fetch(self, *, method, url):
        self.calls.append((method, url))
        return EgressResponse(
            status=200,
            headers={},
            body=b"ok",
        )


def test_agent_egress_requires_agent_scoped_network_capability(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    registry = AgentIsolationRegistry(ledger=ledger)
    _register(registry, agent_id="offline")
    _register(
        registry,
        agent_id="online",
        capabilities=frozenset({
            Capability.FS_READ_PROJECT,
            Capability.NETWORK_OUTBOUND,
        }),
    )

    broker = _FakeEgressBroker()
    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(),
        egress_broker=broker,
        agent_registry=registry,
    )

    with pytest.raises(DispatchDenied):
        dispatcher.fetch_egress_for_agent(
            agent_id="offline",
            url="https://example.com",
        )

    response = dispatcher.fetch_egress_for_agent(
        agent_id="online",
        url="https://example.com",
    )
    assert response.status == 200
    assert broker.calls == [("GET", "https://example.com")]


def test_registry_ledger_becomes_runtime_engine_ledger(tmp_path):
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    registry = AgentIsolationRegistry(ledger=ledger)
    runtime = SimpleNamespace(
        engine=SimpleNamespace(ledger=None),
    )

    CapabilityDispatcher(
        runtime=runtime,
        agent_registry=registry,
    )

    assert runtime.engine.ledger is ledger


def test_runtime_exports_only_nonsecret_agent_identity_hashes():
    action = ActionRequest(
        actor="agent",
        task="test",
        operation="read",
        resource="/workspace/file",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
        metadata={
            "agent_id": "agent",
            "sandbox_id": "sandbox-1",
            "security_context_id": "ctx",
            "model_id": "model-A",
            "intent_hash": "ih",
            "initial_command_hash": "ch",
            "lineage_hash": "lh",
            "initial_intent": "raw intent should not be exported",
            "initial_command": "raw command should not be exported",
        },
    )

    env = BulldogRuntime._sandbox_identity_env(action)
    assert env == {
        "BULL_AGENT_ID": "agent",
        "BULL_SANDBOX_ID": "sandbox-1",
        "BULL_SECURITY_CONTEXT_ID": "ctx",
        "BULL_MODEL_ID": "model-A",
        "BULL_INTENT_HASH": "ih",
        "BULL_INITIAL_COMMAND_HASH": "ch",
        "BULL_LINEAGE_HASH": "lh",
    }
