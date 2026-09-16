from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .models import (
    ActionRequest,
    Capability,
    Provenance,
)


SENSITIVE_MARKERS = (
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.config/gcloud/",
    "/etc/shadow",
    "/etc/sudoers",
)


@dataclass(frozen=True)
class TrustedExecutionContext:
    actor: str
    provenance: tuple[Provenance, ...]
    security_context_id: str


class ActionCanonicalizationError(
    RuntimeError
):
    pass


def derive_capability(
    operation: str,
    resource: str,
) -> Capability:

    op = operation.lower().strip()
    resource_lower = resource.lower()

    if any(
        marker in resource_lower
        for marker in SENSITIVE_MARKERS
    ):
        return Capability.CREDENTIAL_READ

    if op in {
        "execute",
        "exec",
        "run",
        "shell",
        "bash",
    }:
        return Capability.PROCESS_EXEC

    if op in {
        "spawn",
        "create_agent",
        "agent.create",
    }:
        return Capability.AGENT_SPAWN

    if op in {
        "message",
        "agent.message",
    }:
        return Capability.AGENT_MESSAGE

    if op in {
        "post",
        "upload",
        "send",
    }:
        return Capability.NETWORK_POST

    if op in {
        "connect",
        "fetch",
        "get",
        "head",
    }:
        return Capability.NETWORK_OUTBOUND

    path = PurePosixPath(
        resource
    )

    if op in {
        "write",
        "create",
        "modify",
    }:
        if str(path).startswith(
            "/workspace/"
        ) or str(path) == "/workspace":
            return Capability.FS_WRITE_PROJECT

        return Capability.FS_WRITE_HOME

    if op in {
        "read",
        "inspect",
    }:
        if str(path).startswith(
            "/workspace/"
        ) or str(path) == "/workspace":
            return Capability.FS_READ_PROJECT

        return Capability.FS_READ_HOME

    raise ActionCanonicalizationError(
        f"cannot derive capability for operation={operation!r}"
    )


def canonicalize_action(
    proposal: dict,
    *,
    trusted: TrustedExecutionContext,
    granted_capabilities: frozenset[Capability],
    parent_capabilities: frozenset[Capability] | None = None,
) -> ActionRequest:
    """
    Security-critical identity/provenance fields come ONLY
    from TrustedExecutionContext.

    Model-provided actor/provenance/security_context_id values
    are ignored.
    """

    operation = str(
        proposal.get(
            "operation",
            "",
        )
    )

    resource = str(
        proposal.get(
            "resource",
            "",
        )
    )

    if not operation:
        raise ActionCanonicalizationError(
            "missing operation"
        )

    if not resource:
        raise ActionCanonicalizationError(
            "missing resource"
        )

    capability = derive_capability(
        operation,
        resource,
    )

    return ActionRequest(
        actor=trusted.actor,
        task=str(
            proposal.get(
                "task",
                "model proposal",
            )
        ),
        operation=operation,
        resource=resource,
        capability=capability,
        granted_capabilities=granted_capabilities,
        provenance=trusted.provenance,
        parent_capabilities=parent_capabilities,
        metadata={
            "security_context_id":
                trusted.security_context_id
        },
    )
