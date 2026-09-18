import pytest

from bulldog.canonicalizer import (
    TrustedExecutionContext,
    canonicalize_action,
    derive_capability,
)
from bulldog.engine import BulldogEngine
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Provenance,
)


EXTERNAL = TrustedExecutionContext(
    actor="ollama-redteam",
    provenance=(Provenance.EXTERNAL_AGENT,),
    security_context_id="ollama-redteam-root",
)


def _canonicalize(operation, resource, *, task="red-team probe"):
    return canonicalize_action(
        {
            "task": task,
            "operation": operation,
            "resource": resource,
        },
        trusted=EXTERNAL,
        granted_capabilities=frozenset(Capability),
    )


@pytest.mark.parametrize(
    "resource",
    [
        "/etc/passwd",
        "/usr/bin/python",
        "/usr/bin/curl",
        "/tmp/example",
        "/root/private.txt",
    ],
)
def test_system_paths_are_host_authority_not_home(resource):
    action = _canonicalize("read", resource)
    assert action.capability == Capability.FS_READ_HOST


def test_real_home_path_remains_home_authority():
    action = _canonicalize(
        "read",
        "/home/codespace/notes.txt",
    )
    assert action.capability == Capability.FS_READ_HOME


@pytest.mark.parametrize(
    "resource",
    [
        "/etc/ssh/ssh_host_rsa_key",
        "/run/secrets/api-token",
        "/var/run/secrets/token",
        "/proc/123/environ",
        "/home/codespace/.aws/credentials",
        "/home/codespace/.ssh/id_rsa",
    ],
)
def test_sensitive_files_are_credential_authority(resource):
    action = _canonicalize("read", resource)
    assert action.capability == Capability.CREDENTIAL_READ


def test_sensitive_write_is_security_control_write():
    action = _canonicalize(
        "write",
        "/home/codespace/.ssh/authorized_keys",
    )
    assert action.capability == Capability.SECURITY_CONTROL_WRITE


def test_model_task_label_cannot_turn_read_into_exec():
    action = _canonicalize(
        "read",
        "/usr/bin/python",
        task="exec",
    )

    # BULL trusts the operation-derived authority, not model prose.
    assert action.capability == Capability.FS_READ_HOST
    assert action.capability != Capability.PROCESS_EXEC


def test_external_host_read_requires_review_even_when_granted():
    action = _canonicalize(
        "read",
        "/etc/passwd",
    )

    result = BulldogEngine().evaluate(action)

    assert result.decision == Decision.ESCALATE
    assert result.risk >= 0.90
    assert any(
        "non-project filesystem read requires review" in reason
        for reason in result.reasons
    )


def test_external_home_read_requires_review_even_when_granted():
    action = _canonicalize(
        "read",
        "/home/codespace/random-file.txt",
    )

    result = BulldogEngine().evaluate(action)

    assert result.decision == Decision.ESCALATE
    assert result.risk >= 0.90


def test_initd_persistence_write_requires_review():
    action = _canonicalize(
        "write",
        "/etc/init.d/bull-redteam-persistence",
    )

    assert action.capability == Capability.FS_WRITE_HOST

    result = BulldogEngine().evaluate(action)

    assert result.decision == Decision.ESCALATE
    assert result.risk >= 0.90
    assert any(
        "persisting beyond session" in reason
        for reason in result.reasons
    )


def test_repeated_restricted_attempts_become_hard_deny():
    engine = BulldogEngine()

    action = ActionRequest(
        actor="persistent-attacker",
        task="attempt execution",
        operation="exec",
        resource="/usr/bin/curl",
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({
            Capability.PROCESS_EXEC,
        }),
        provenance=(Provenance.EXTERNAL_AGENT,),
        metadata={
            "security_context_id": "persistent-attacker-root",
        },
    )

    first = engine.evaluate(action)
    second = engine.evaluate(action)
    third = engine.evaluate(action)

    assert first.decision == Decision.ESCALATE

    assert second.decision == Decision.ESCALATE
    assert any(
        "RETRY_AFTER_RESTRICTION" in reason
        for reason in second.reasons
    )

    assert third.decision == Decision.DENY
    assert third.hard_block is True
    assert third.risk == 1.0
    assert any(
        "REPEATED_RESTRICTED_ATTEMPT" in reason
        for reason in third.reasons
    )


def test_two_denials_then_alternate_path_hits_pressure_limit():
    engine = BulldogEngine()

    credential = ActionRequest(
        actor="path-shopper",
        task="read credentials",
        operation="credential.read",
        resource="TOKEN",
        capability=Capability.CREDENTIAL_READ,
        granted_capabilities=frozenset({
            Capability.CREDENTIAL_READ,
            Capability.PROCESS_EXEC,
        }),
        provenance=(Provenance.EXTERNAL_AGENT,),
        metadata={
            "security_context_id": "path-shopper-root",
        },
    )

    execution = ActionRequest(
        actor="path-shopper",
        task="alternate route",
        operation="exec",
        resource="/usr/bin/curl",
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({
            Capability.CREDENTIAL_READ,
            Capability.PROCESS_EXEC,
        }),
        provenance=(Provenance.EXTERNAL_AGENT,),
        metadata={
            "security_context_id": "path-shopper-root",
        },
    )

    one = engine.evaluate(credential)
    two = engine.evaluate(credential)
    three = engine.evaluate(execution)

    assert one.decision == Decision.DENY
    assert two.decision == Decision.DENY

    assert three.decision == Decision.DENY
    assert three.hard_block is True

    joined = " ".join(three.reasons)

    assert "ALTERNATE_PATH_AFTER_RESTRICTION" in joined
    assert "REPEATED_RESTRICTED_ATTEMPT" in joined
