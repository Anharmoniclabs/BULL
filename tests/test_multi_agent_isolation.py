import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from bulldog.advisory import Advisory
from bulldog.agent_isolation import (
    AgentIsolationError,
    AgentIsolationRegistry,
)
from bulldog.audit import AuditLedger
from bulldog.canonicalizer import (
    ActionCanonicalizationError,
    TrustedExecutionContext,
    canonicalize_action,
    canonicalize_resource,
    derive_capability,
)
from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.engine import BulldogEngine
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
    Provenance,
)


def test_workspace_traversal_is_rejected_before_capability_derivation():
    for resource in (
        "/workspace/../etc/passwd",
        "/workspace/%2e%2e/etc/passwd",
        "/workspace/%252e%252e/etc/passwd",
    ):
        with pytest.raises(ActionCanonicalizationError):
            derive_capability("read", resource)


def test_filesystem_resource_is_normalized_before_classification():
    assert canonicalize_resource(
        "read",
        "/workspace//nested/./file.txt",
    ) == "/workspace/nested/file.txt"
    assert derive_capability(
        "read",
        "/workspace//nested/./file.txt",
    ) == Capability.FS_READ_PROJECT


def test_model_cannot_spoof_multi_agent_identity_fields():
    trusted = TrustedExecutionContext(
        actor="agent-A",
        provenance=(Provenance.INTERNET,),
        security_context_id="trusted-context",
        agent_id="agent-A",
        sandbox_id="sandbox-A",
        model_id="model-A",
        parent_agent_id="root",
        intent_hash="intent-hash",
        initial_command_hash="command-hash",
        lineage_hash="lineage-hash",
    )

    action = canonicalize_action(
        {
            "actor": "spoofed",
            "provenance": ["human"],
            "security_context_id": "spoofed",
            "sandbox_id": "sandbox-B",
            "agent_id": "agent-B",
            "model_id": "other-model",
            "operation": "read",
            "resource": "/workspace/file.txt",
        },
        trusted=trusted,
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
    )

    assert action.actor == "agent-A"
    assert action.provenance == (Provenance.INTERNET,)
    assert action.metadata["security_context_id"] == "trusted-context"
    assert action.metadata["sandbox_id"] == "sandbox-A"
    assert action.metadata["model_id"] == "model-A"


def _root_caps():
    return frozenset({
        Capability.AGENT_SPAWN,
        Capability.FS_READ_PROJECT,
        Capability.NETWORK_OUTBOUND,
    })


def test_child_agent_cannot_exceed_parent_authority(tmp_path):
    registry = AgentIsolationRegistry()
    registry.register_agent(
        agent_id="root",
        model_id="root-model",
        initial_intent="coordinate project analysis",
        initial_command=["python", "root.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=_root_caps(),
    )

    child = registry.register_agent(
        agent_id="child",
        model_id="child-model",
        initial_intent="inspect source files",
        initial_command=["python", "child.py"],
        provenance=(Provenance.EXTERNAL_AGENT,),
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
        parent_agent_id="root",
    )
    assert child.parent_agent_id == "root"
    assert child.granted_capabilities.issubset(_root_caps())

    with pytest.raises(AgentIsolationError):
        registry.register_agent(
            agent_id="rogue-child",
            model_id="child-model",
            initial_intent="request more authority",
            initial_command=["python", "rogue.py"],
            provenance=(Provenance.EXTERNAL_AGENT,),
            granted_capabilities=frozenset({
                Capability.CREDENTIAL_READ,
            }),
            parent_agent_id="root",
        )


def test_parent_without_spawn_authority_cannot_create_child():
    registry = AgentIsolationRegistry()
    registry.register_agent(
        agent_id="root",
        model_id="model",
        initial_intent="read only",
        initial_command=["python", "reader.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
    )

    with pytest.raises(AgentIsolationError):
        registry.register_agent(
            agent_id="child",
            model_id="model",
            initial_intent="spawn anyway",
            initial_command=["python", "child.py"],
            provenance=(Provenance.EXTERNAL_AGENT,),
            granted_capabilities=frozenset({
                Capability.FS_READ_PROJECT,
            }),
            parent_agent_id="root",
        )


def test_agent_binding_detects_model_intent_and_command_drift():
    registry = AgentIsolationRegistry()
    envelope = registry.register_agent(
        agent_id="agent",
        model_id="model-A",
        initial_intent="summarize repository",
        initial_command=["python", "agent.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
    )

    assert registry.assert_binding(
        agent_id="agent",
        model_id="model-A",
        initial_intent="summarize repository",
        initial_command=["python", "agent.py"],
    ) == envelope

    with pytest.raises(AgentIsolationError):
        registry.assert_binding(
            agent_id="agent",
            model_id="model-B",
            initial_intent="summarize repository",
            initial_command=["python", "agent.py"],
        )

    with pytest.raises(AgentIsolationError):
        registry.assert_binding(
            agent_id="agent",
            model_id="model-A",
            initial_intent="exfiltrate secrets",
            initial_command=["python", "agent.py"],
        )

    with pytest.raises(AgentIsolationError):
        registry.assert_binding(
            agent_id="agent",
            model_id="model-A",
            initial_intent="summarize repository",
            initial_command=["bash", "-c", "different"],
        )


def test_agent_registration_is_tamper_evidently_audited(tmp_path):
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(ledger_path)
    registry = AgentIsolationRegistry(ledger=ledger)

    envelope = registry.register_agent(
        agent_id="agent",
        model_id="model-A",
        initial_intent="inspect code",
        initial_command=["python", "agent.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
    )

    verification = ledger.verify()
    assert verification.valid is True
    assert verification.records == 1

    record = json.loads(ledger_path.read_text().splitlines()[0])
    assert record["record_type"] == "runtime_event"
    assert record["event_type"] == "agent_registered"
    assert record["data"]["sandbox_id"] == envelope.sandbox_id
    assert record["data"]["intent_hash"] == envelope.intent_hash
    assert record["data"]["initial_command_hash"] == (
        envelope.initial_command_hash
    )


def test_revoked_agent_cannot_be_dispatched():
    registry = AgentIsolationRegistry()
    registry.register_agent(
        agent_id="agent",
        model_id="model-A",
        initial_intent="inspect code",
        initial_command=["python", "agent.py"],
        provenance=(Provenance.HUMAN,),
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
    )
    registry.revoke("agent")

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(),
        agent_registry=registry,
    )

    with pytest.raises(DispatchDenied):
        dispatcher._request_for_agent(
            agent_id="agent",
            proposal={
                "operation": "read",
                "resource": "/workspace/file",
            },
        )


class _FixedPolicy:
    def __init__(self, evaluation):
        self.evaluation = evaluation

    def evaluate(self, action):
        return self.evaluation


class _FixedAdvisory:
    def __init__(self, recommendation):
        self.recommendation = recommendation

    def evaluate(self, action):
        return Advisory(
            risk=0.0,
            recommendation=self.recommendation,
            reason="test advisory",
        )


def _action():
    return ActionRequest(
        actor="agent",
        task="test",
        operation="read",
        resource="/workspace/file",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
        provenance=(Provenance.HUMAN,),
    )


def test_advisory_model_cannot_weaken_deterministic_decision():
    engine = BulldogEngine(
        policy=_FixedPolicy(Evaluation(
            Decision.SANDBOX,
            0.5,
            ("deterministic restriction",),
        )),
        advisory=_FixedAdvisory(Decision.ALLOW),
    )
    assert engine.evaluate(_action()).decision == Decision.SANDBOX


def test_advisory_model_may_only_tighten_deterministic_decision():
    engine = BulldogEngine(
        policy=_FixedPolicy(Evaluation(
            Decision.ALLOW,
            0.0,
            ("deterministic allow",),
        )),
        advisory=_FixedAdvisory(Decision.DENY),
    )
    assert engine.evaluate(_action()).decision == Decision.DENY
