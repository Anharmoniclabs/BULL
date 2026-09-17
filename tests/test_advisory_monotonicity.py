from bulldog.advisory import Advisory
from bulldog.engine import BulldogEngine
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Provenance,
)


class FixedAdvisory:
    def __init__(self, recommendation: Decision, risk: float = 0.0):
        self.recommendation = recommendation
        self.risk = risk

    def evaluate(self, action):
        return Advisory(
            risk=self.risk,
            recommendation=self.recommendation,
            reason="test advisory",
        )


def _action(
    *,
    capability: Capability,
    resource: str,
    provenance=(Provenance.HUMAN,),
):
    return ActionRequest(
        actor="agent",
        task="test",
        operation=(
            "execute"
            if capability == Capability.PROCESS_EXEC
            else "agent.create"
            if capability == Capability.AGENT_SPAWN
            else "read"
        ),
        resource=resource,
        capability=capability,
        granted_capabilities=frozenset({capability}),
        provenance=provenance,
    )


def test_advisory_allow_cannot_lower_sandbox_policy():
    engine = BulldogEngine(
        advisory=FixedAdvisory(Decision.ALLOW),
    )
    result = engine.evaluate(
        _action(
            capability=Capability.AGENT_SPAWN,
            resource="/workspace/helper",
        )
    )
    assert result.decision == Decision.SANDBOX


def test_advisory_allow_cannot_lower_escalate_policy():
    engine = BulldogEngine(
        advisory=FixedAdvisory(Decision.ALLOW),
    )
    result = engine.evaluate(
        _action(
            capability=Capability.PROCESS_EXEC,
            resource="/bin/sh",
            provenance=(Provenance.INTERNET,),
        )
    )
    assert result.decision == Decision.ESCALATE


def test_advisory_allow_cannot_override_hard_deny():
    engine = BulldogEngine(
        advisory=FixedAdvisory(Decision.ALLOW),
    )
    result = engine.evaluate(
        _action(
            capability=Capability.CREDENTIAL_READ,
            resource="/home/user/.ssh/id_rsa",
            provenance=(Provenance.INTERNET,),
        )
    )
    assert result.decision == Decision.DENY
    assert result.hard_block is True


def test_advisory_can_tighten_allow_to_deny_but_not_grant_authority():
    engine = BulldogEngine(
        advisory=FixedAdvisory(Decision.DENY, risk=1.0),
    )
    action = ActionRequest(
        actor="agent",
        task="read",
        operation="read",
        resource="/workspace/README.md",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
    )
    result = engine.evaluate(action)
    assert result.decision == Decision.DENY
