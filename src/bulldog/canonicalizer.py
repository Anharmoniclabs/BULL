from __future__ import annotations

from dataclasses import dataclass
import posixpath
from pathlib import PurePosixPath
from urllib.parse import unquote

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

NETWORK_OPERATIONS = {
    "post",
    "upload",
    "send",
    "connect",
    "fetch",
    "get",
    "head",
}


@dataclass(frozen=True)
class TrustedExecutionContext:
    """
    Host-authenticated execution identity.

    These fields are trusted runtime state. Model output is never allowed to
    overwrite them during canonicalization.
    """

    actor: str
    provenance: tuple[Provenance, ...]
    security_context_id: str

    agent_id: str | None = None
    sandbox_id: str | None = None
    model_id: str | None = None
    parent_agent_id: str | None = None
    intent_hash: str | None = None
    initial_command_hash: str | None = None
    lineage_hash: str | None = None
    initial_intent: str | None = None
    initial_command: str | None = None

    def audit_metadata(self) -> dict[str, str]:
        values = {
            "security_context_id": self.security_context_id,
            "agent_id": self.agent_id,
            "sandbox_id": self.sandbox_id,
            "model_id": self.model_id,
            "parent_agent_id": self.parent_agent_id,
            "intent_hash": self.intent_hash,
            "initial_command_hash": self.initial_command_hash,
            "lineage_hash": self.lineage_hash,
            "initial_intent": self.initial_intent,
            "initial_command": self.initial_command,
        }
        return {
            key: str(value)
            for key, value in values.items()
            if value is not None
        }


class ActionCanonicalizationError(RuntimeError):
    pass


def _decode_path(resource: str) -> str:
    """Decode percent-encoding to a fixed point with a small hard bound."""
    decoded = resource
    for _ in range(4):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def canonicalize_resource(
    operation: str,
    resource: str,
) -> str:
    """
    Canonicalize filesystem-like resources before capability derivation.

    BULL uses a virtual POSIX namespace rooted at /workspace. We deliberately
    perform lexical canonicalization here rather than resolving against the host
    filesystem. Runtime filesystem manifests independently reject symlinks,
    hardlinks, mount crossings, and special files before execution.
    """

    op = operation.lower().strip()
    raw = str(resource).strip()

    if not raw:
        raise ActionCanonicalizationError("missing resource")

    if "\x00" in raw:
        raise ActionCanonicalizationError("NUL byte in resource")

    if op in NETWORK_OPERATIONS:
        return raw

    # Non-path logical resources are preserved. Absolute filesystem resources
    # are canonicalized and traversal is rejected before classification.
    if not raw.startswith("/"):
        return raw

    decoded = _decode_path(raw)
    parts = PurePosixPath(decoded).parts

    if ".." in parts:
        raise ActionCanonicalizationError(
            "path traversal is not allowed"
        )

    normalized = posixpath.normpath(decoded)

    if not normalized.startswith("/"):
        raise ActionCanonicalizationError(
            "filesystem resource must remain absolute"
        )

    return normalized


def derive_capability(
    operation: str,
    resource: str,
) -> Capability:
    op = operation.lower().strip()
    canonical_resource = canonicalize_resource(
        operation,
        resource,
    )
    resource_lower = canonical_resource.lower()

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

    path = PurePosixPath(canonical_resource)

    if op in {
        "write",
        "create",
        "modify",
    }:
        if path == PurePosixPath("/workspace") or (
            PurePosixPath("/workspace") in path.parents
        ):
            return Capability.FS_WRITE_PROJECT
        return Capability.FS_WRITE_HOME

    if op in {
        "read",
        "inspect",
    }:
        if path == PurePosixPath("/workspace") or (
            PurePosixPath("/workspace") in path.parents
        ):
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
    Convert an untrusted model proposal into a trusted ActionRequest.

    Security-critical identity/provenance fields come ONLY from
    TrustedExecutionContext. Model-provided actor, provenance, sandbox,
    lineage, and security-context values are ignored.
    """

    operation = str(proposal.get("operation", "")).strip()
    resource = str(proposal.get("resource", "")).strip()

    if not operation:
        raise ActionCanonicalizationError("missing operation")

    canonical_resource = canonicalize_resource(
        operation,
        resource,
    )

    capability = derive_capability(
        operation,
        canonical_resource,
    )

    return ActionRequest(
        actor=trusted.actor,
        task=str(proposal.get("task", "model proposal")),
        operation=operation,
        resource=canonical_resource,
        capability=capability,
        granted_capabilities=granted_capabilities,
        provenance=trusted.provenance,
        parent_capabilities=parent_capabilities,
        metadata=trusted.audit_metadata(),
    )
