from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from .security_flags import SecurityFlag


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANDBOX = "SANDBOX"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class Provenance(str, Enum):
    HUMAN = "human"
    LOCAL_TRUSTED = "local_trusted"
    REPOSITORY = "repository"
    INTERNET = "internet"
    EXTERNAL_AGENT = "external_agent"
    UNKNOWN = "unknown"


class Capability(str, Enum):
    FS_READ_PROJECT = "fs.read.project"
    FS_WRITE_PROJECT = "fs.write.project"
    FS_READ_HOME = "fs.read.home"
    FS_WRITE_HOME = "fs.write.home"
    CREDENTIAL_READ = "credential.read"
    PROCESS_EXEC = "process.exec"
    NETWORK_OUTBOUND = "network.outbound"
    NETWORK_POST = "network.post"
    PACKAGE_INSTALL = "package.install"
    AGENT_SPAWN = "agent.spawn"
    AGENT_MESSAGE = "agent.message"
    SECURITY_CONTROL_WRITE = "security_control.write"


@dataclass(frozen=True)
class ActionRequest:
    actor: str
    task: str
    operation: str
    resource: str
    capability: Capability
    granted_capabilities: frozenset[Capability]
    provenance: tuple[Provenance, ...] = (Provenance.UNKNOWN,)
    parent_capabilities: frozenset[Capability] | None = None
    irreversible: bool = False
    external_side_effect: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    # HARDENING: these fields must be populated by the trusted host adapter,
    # never by model output. The policy fails closed when context is not verified.
    security_context_verified: bool = False
    resolved_resource: str | None = None
    secret_taint: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "ActionRequest":
        return cls(
            actor=data["actor"],
            task=data["task"],
            operation=data["operation"],
            resource=data["resource"],
            capability=Capability(data["capability"]),
            granted_capabilities=frozenset(Capability(x) for x in data.get("granted_capabilities", [])),
            provenance=tuple(Provenance(x) for x in data.get("provenance", ["unknown"])),
            parent_capabilities=(
                frozenset(Capability(x) for x in data["parent_capabilities"])
                if data.get("parent_capabilities") is not None
                else None
            ),
            irreversible=bool(data.get("irreversible", False)),
            external_side_effect=bool(data.get("external_side_effect", False)),
            metadata={str(k): str(v) for k, v in data.get("metadata", {}).items()},
            security_context_verified=bool(data.get("security_context_verified", False)),
            resolved_resource=(str(data["resolved_resource"]) if data.get("resolved_resource") is not None else None),
            secret_taint=bool(data.get("secret_taint", False)),
        )


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    risk: float
    reasons: tuple[str, ...]
    hard_block: bool = False
    flags: tuple[SecurityFlag, ...] = ()

    @property
    def plain_english_flags(self) -> tuple[str, ...]:
        return tuple(item.render() for item in self.flags)


def has_external_provenance(values: Iterable[Provenance]) -> bool:
    return any(v in {Provenance.INTERNET, Provenance.EXTERNAL_AGENT, Provenance.UNKNOWN} for v in values)
