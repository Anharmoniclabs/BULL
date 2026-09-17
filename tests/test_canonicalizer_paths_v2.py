import pytest

from bulldog.canonicalizer import (
    ActionCanonicalizationError,
    TrustedExecutionContext,
    canonicalize_action,
    derive_capability,
)
from bulldog.models import Capability, Provenance


TRUSTED = TrustedExecutionContext(
    actor="host-agent",
    provenance=(Provenance.HUMAN,),
    security_context_id="trusted-context",
)


def _canonicalize(resource: str):
    return canonicalize_action(
        {
            "task": "inspect project",
            "operation": "read",
            "resource": resource,
        },
        trusted=TRUSTED,
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
            Capability.FS_READ_HOME,
            Capability.CREDENTIAL_READ,
        }),
    )


@pytest.mark.parametrize(
    "resource",
    [
        "/workspace/../etc/passwd",
        "/workspace/%2e%2e/etc/passwd",
        "/workspace/%252e%252e/etc/passwd",
        "\\workspace\\..\\etc\\passwd",
    ],
)
def test_traversal_never_classifies_as_project(resource):
    with pytest.raises(ActionCanonicalizationError):
        _canonicalize(resource)


def test_project_path_is_canonicalized_before_classification():
    action = _canonicalize("/workspace//src/./main.py")
    assert action.resource == "/workspace/src/main.py"
    assert action.capability == Capability.FS_READ_PROJECT


def test_sensitive_path_wins_over_process_operation():
    capability = derive_capability(
        "execute",
        "/home/user/.ssh/id_rsa",
    )
    assert capability == Capability.CREDENTIAL_READ


def test_untrusted_domain_metadata_cannot_override_host_context():
    trusted = TrustedExecutionContext(
        actor="host-agent",
        provenance=(Provenance.INTERNET,),
        security_context_id="root-domain:ROOT",
        domain_id="DOMAIN-A",
        root_domain_id="ROOT",
        parent_domain_id="PARENT",
        initial_intent_hash="abc123",
        initial_command_hash="def456",
        spawn_depth=2,
    )

    action = canonicalize_action(
        {
            "task": "inspect project",
            "operation": "read",
            "resource": "/workspace/file.txt",
            "actor": "spoofed",
            "domain_id": "DOMAIN-B",
            "root_domain_id": "OTHER",
            "security_context_id": "attacker",
            "provenance": ["human"],
        },
        trusted=trusted,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
    )

    assert action.actor == "host-agent"
    assert action.provenance == (Provenance.INTERNET,)
    assert action.metadata["domain_id"] == "DOMAIN-A"
    assert action.metadata["root_domain_id"] == "ROOT"
    assert action.metadata["security_context_id"] == "root-domain:ROOT"
    assert action.metadata["spawn_depth"] == "2"
