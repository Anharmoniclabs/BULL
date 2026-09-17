from __future__ import annotations

from dataclasses import dataclass
import posixpath
from urllib.parse import unquote, urlsplit

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

_PATH_OPERATIONS = {
    "read",
    "inspect",
    "write",
    "create",
    "modify",
}


@dataclass(frozen=True)
class TrustedExecutionContext:
    actor: str
    provenance: tuple[Provenance, ...]
    security_context_id: str

    # Optional host-issued multi-agent security-domain metadata.
    # These values are never accepted from a model proposal.
    domain_id: str | None = None
    root_domain_id: str | None = None
    parent_domain_id: str | None = None
    initial_intent_hash: str | None = None
    initial_command_hash: str | None = None
    model_id: str | None = None
    model_id_hash: str | None = None
    domain_fingerprint: str | None = None
    spawn_depth: int = 0


class ActionCanonicalizationError(RuntimeError):
    pass


def _decode_resource(value: str) -> str:
    """
    Decode percent-encoding repeatedly so nested encodings cannot hide
    path traversal from the security classifier. The result is bounded to
    a few rounds; deeply nested encodings are rejected as ambiguous.
    """

    if "\x00" in value:
        raise ActionCanonicalizationError("NUL byte in resource")

    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            return decoded
        decoded = next_value

    if unquote(decoded) != decoded:
        raise ActionCanonicalizationError(
            "resource contains excessively nested percent-encoding"
        )

    return decoded


def canonicalize_filesystem_resource(resource: str) -> str:
    decoded = _decode_resource(resource).replace("\\", "/")

    if not decoded.startswith("/"):
        raise ActionCanonicalizationError(
            "filesystem resource must be an absolute path"
        )

    if any(part == ".." for part in decoded.split("/")):
        raise ActionCanonicalizationError(
            "parent-directory traversal in filesystem resource"
        )

    normalized = posixpath.normpath(decoded)

    if not normalized.startswith("/"):
        raise ActionCanonicalizationError(
            "filesystem resource escaped absolute path namespace"
        )

    return normalized


def canonicalize_resource(operation: str, resource: str) -> str:
    op = operation.lower().strip()
    raw = str(resource).strip()

    if not raw:
        raise ActionCanonicalizationError("missing resource")

    if op in _PATH_OPERATIONS or raw.startswith(("/", "\\")):
        return canonicalize_filesystem_resource(raw)

    return _decode_resource(raw)


def derive_capability(operation: str, resource: str) -> Capability:
    op = operation.lower().strip()
    canonical_resource = canonicalize_resource(op, resource)
    resource_lower = canonical_resource.lower()

    if any(marker in resource_lower for marker in SENSITIVE_MARKERS):
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
        parsed = urlsplit(canonical_resource)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            raise ActionCanonicalizationError(
                "unsupported network resource scheme"
            )
        return Capability.NETWORK_OUTBOUND

    if op in {"write", "create", "modify"}:
        if (
            canonical_resource == "/workspace"
            or canonical_resource.startswith("/workspace/")
        ):
            return Capability.FS_WRITE_PROJECT
        return Capability.FS_WRITE_HOME

    if op in {"read", "inspect"}:
        if (
            canonical_resource == "/workspace"
            or canonical_resource.startswith("/workspace/")
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

    Security-critical identity, provenance and security-domain fields come
    ONLY from TrustedExecutionContext. Model-provided values for those fields
    are ignored.
    """

    operation = str(proposal.get("operation", "")).strip()
    resource = str(proposal.get("resource", "")).strip()

    if not operation:
        raise ActionCanonicalizationError("missing operation")

    canonical_resource = canonicalize_resource(operation, resource)
    capability = derive_capability(operation, canonical_resource)

    metadata = {
        "security_context_id": trusted.security_context_id,
    }

    trusted_metadata = {
        "domain_id": trusted.domain_id,
        "root_domain_id": trusted.root_domain_id,
        "parent_domain_id": trusted.parent_domain_id,
        "initial_intent_hash": trusted.initial_intent_hash,
        "initial_command_hash": trusted.initial_command_hash,
        "model_id": trusted.model_id,
        "model_id_hash": trusted.model_id_hash,
        "domain_fingerprint": trusted.domain_fingerprint,
        "spawn_depth": str(trusted.spawn_depth),
    }

    metadata.update(
        {
            key: str(value)
            for key, value in trusted_metadata.items()
            if value is not None
        }
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
        metadata=metadata,
    )
