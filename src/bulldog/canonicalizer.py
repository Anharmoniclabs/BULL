from __future__ import annotations

from dataclasses import dataclass
import posixpath
import unicodedata
from urllib.parse import unquote, urlsplit

from .models import ActionRequest, Capability, Provenance


SENSITIVE_MARKERS = (
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.config/gcloud/",
    "/.kube/config",
    "/.docker/config.json",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/ssh_host_",
    "/run/secrets/",
    "/var/run/secrets/",
)

_PATH_OPERATIONS = {"read", "inspect", "write", "create", "modify"}
_SECRET_OPERATIONS = {"secret.get", "credential.get", "credential.read"}


def _is_under_root(resource: str, root: str) -> bool:
    root = root.rstrip("/")
    return resource == root or resource.startswith(root + "/")


def _is_project_path(resource: str) -> bool:
    return _is_under_root(resource, "/workspace")


def _is_home_path(resource: str) -> bool:
    # /root is intentionally NOT treated as ordinary user-home authority.
    # Root-owned files remain host authority.
    return _is_under_root(resource, "/home")


def is_sensitive_filesystem_resource(resource: str) -> bool:
    value = str(resource).lower()

    if any(marker in value for marker in SENSITIVE_MARKERS):
        return True

    # /proc/<pid>/environ can expose process credentials/tokens.
    if (
        value.startswith("/proc/")
        and value.endswith("/environ")
    ):
        return True

    return False


@dataclass(frozen=True)
class TrustedExecutionContext:
    actor: str
    provenance: tuple[Provenance, ...]
    security_context_id: str
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


def _reject_unicode_separator_or_dot_folding(value: str) -> None:
    folded = unicodedata.normalize("NFKC", value)
    if folded == value:
        return
    for marker in (".", "/", "\\"):
        if folded.count(marker) > value.count(marker):
            raise ActionCanonicalizationError(
                "filesystem resource has Unicode normalization ambiguity"
            )


def canonicalize_filesystem_resource(resource: str) -> str:
    decoded = _decode_resource(resource)
    _reject_unicode_separator_or_dot_folding(decoded)
    decoded = decoded.replace("\\", "/")

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
    is_filesystem_target = canonical_resource.startswith("/")

    if op in _SECRET_OPERATIONS:
        return Capability.CREDENTIAL_READ

    # Writes to credential/security material are not "reads".
    # They alter a trusted security resource and receive their own
    # high-risk authority.
    if (
        op in {"write", "create", "modify"}
        and is_filesystem_target
        and is_sensitive_filesystem_resource(canonical_resource)
    ):
        return Capability.SECURITY_CONTROL_WRITE

    if (
        is_filesystem_target
        and is_sensitive_filesystem_resource(canonical_resource)
    ):
        return Capability.CREDENTIAL_READ

    if op in {"execute", "exec", "run", "shell", "bash"}:
        return Capability.PROCESS_EXEC
    if op in {"spawn", "create_agent", "agent.create"}:
        return Capability.AGENT_SPAWN
    if op in {"message", "agent.message"}:
        return Capability.AGENT_MESSAGE
    if op in {"post", "upload", "send"}:
        return Capability.NETWORK_POST
    if op in {"connect", "fetch", "get", "head"}:
        parsed = urlsplit(canonical_resource)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            raise ActionCanonicalizationError(
                "unsupported network resource scheme"
            )
        return Capability.NETWORK_OUTBOUND

    if op in {"write", "create", "modify"}:
        if _is_project_path(canonical_resource):
            return Capability.FS_WRITE_PROJECT
        if _is_home_path(canonical_resource):
            return Capability.FS_WRITE_HOME
        return Capability.FS_WRITE_HOST

    if op in {"read", "inspect"}:
        if _is_project_path(canonical_resource):
            return Capability.FS_READ_PROJECT
        if _is_home_path(canonical_resource):
            return Capability.FS_READ_HOME
        return Capability.FS_READ_HOST

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
    operation = str(proposal.get("operation", "")).strip()
    resource = str(proposal.get("resource", "")).strip()
    if not operation:
        raise ActionCanonicalizationError("missing operation")

    canonical_resource = canonicalize_resource(operation, resource)
    capability = derive_capability(operation, canonical_resource)
    metadata = {"security_context_id": trusted.security_context_id}
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
