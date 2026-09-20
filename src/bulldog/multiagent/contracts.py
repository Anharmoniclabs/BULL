"""Shared contracts for the BULL multi-agent system.

These types are deliberately self-contained (stdlib only) so the
multi-agent layer works with or without the rest of bulldog.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    """Outcome of a policy or audit evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


class Severity(str, Enum):
    """Severity scale for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Capability:
    """A named permission an agent may hold."""

    name: str
    description: str = ""

    def __str__(self) -> str:
        return self.name


CAP_COORDINATE = Capability("coordinate", "Decompose tasks and route work")
CAP_AUDIT = Capability("audit", "Inspect payloads and results for unauthorized logic")
CAP_POLICY = Capability("policy", "Render allow/deny verdicts on proposed actions")
CAP_EXECUTE = Capability("execute", "Run approved actions in the restricted executor")
CAP_VERIFY = Capability("verify", "Independently verify executed results")
CAP_HONEYTOKEN = Capability(
    "honeytoken",
    "Mint and monitor host-owned canaries without granting execution authority",
)


@dataclass(frozen=True)
class AgentIdentity:
    """Immutable identity and capability set for one agent."""

    agent_id: str
    name: str
    capabilities: frozenset = frozenset()

    @classmethod
    def new(
        cls,
        name: str,
        capabilities: Any = (),
        agent_id: Optional[str] = None,
    ) -> "AgentIdentity":
        return cls(
            agent_id=agent_id or f"{name.lower()}-{uuid.uuid4().hex[:8]}",
            name=name,
            capabilities=frozenset(capabilities),
        )

    def has(self, capability: Capability) -> bool:
        return capability in self.capabilities


@dataclass
class Envelope:
    """A message routed between agents over the bus."""

    message_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    sender: str = "system"
    recipient: str = "*"
    message_type: str = "task"
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    hops: int = 0

    def forwarded(
        self, recipient: str, message_type: str, payload: Dict[str, Any]
    ) -> "Envelope":
        """Create a derived envelope that keeps the trace id and counts hops."""
        return Envelope(
            trace_id=self.trace_id,
            sender=self.sender,
            recipient=recipient,
            message_type=message_type,
            payload=payload,
            hops=self.hops + 1,
        )


@dataclass
class Finding:
    """A single observation produced by an agent."""

    agent_id: str
    severity: Severity
    code: str
    summary: str
    detail: str = ""


@dataclass
class AgentResult:
    """Uniform return type for every agent handler."""

    agent_id: str
    success: bool
    verdict: Verdict = Verdict.ALLOW
    output: Any = None
    findings: List[Finding] = field(default_factory=list)
    duration_s: float = 0.0


@dataclass
class TraceEvent:
    """Structured audit-trail record emitted by the bus."""

    timestamp: float = field(default_factory=time.time)
    trace_id: str = ""
    agent_id: str = ""
    event: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
