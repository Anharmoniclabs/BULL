"""BULL multi-agent system: layered agents that block unauthorized logic."""

from .agents import (
    AuditorAgent,
    BaseAgent,
    CoordinatorAgent,
    ExecutorAgent,
    PolicyAgent,
    VerifierAgent,
)
from .bus import DeliveryError, MessageBus
from .contracts import (
    CAP_AUDIT,
    CAP_COORDINATE,
    CAP_EXECUTE,
    CAP_HONEYTOKEN,
    CAP_POLICY,
    CAP_VERIFY,
    AgentIdentity,
    AgentResult,
    Capability,
    Envelope,
    Finding,
    Severity,
    Verdict,
)
from .honeytoken import HoneyTokenAgent, HoneyTokenLeak
from .system import MultiAgentSystem, RunReport, StepReport

__all__ = [
    "AuditorAgent",
    "BaseAgent",
    "CoordinatorAgent",
    "ExecutorAgent",
    "PolicyAgent",
    "VerifierAgent",
    "HoneyTokenAgent",
    "HoneyTokenLeak",
    "DeliveryError",
    "MessageBus",
    "MultiAgentSystem",
    "RunReport",
    "StepReport",
    "AgentIdentity",
    "AgentResult",
    "Capability",
    "Envelope",
    "Finding",
    "Severity",
    "Verdict",
    "CAP_AUDIT",
    "CAP_COORDINATE",
    "CAP_EXECUTE",
    "CAP_HONEYTOKEN",
    "CAP_POLICY",
    "CAP_VERIFY",
]
