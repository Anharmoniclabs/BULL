"""Built-in agents for the BULL multi-agent system.

Pipeline: Coordinator -> Policy -> Executor -> Auditor + Verifier.
Nothing executes unless the policy agent allows it, and no result is
accepted until the auditor and the independent verifier sign off -
the multi-agent expression of BULL's core mission.
"""

from __future__ import annotations

import abc
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from .bus import MessageBus
from .contracts import (
    CAP_AUDIT,
    CAP_COORDINATE,
    CAP_EXECUTE,
    CAP_POLICY,
    CAP_VERIFY,
    AgentIdentity,
    AgentResult,
    Envelope,
    Finding,
    Severity,
    Verdict,
)

logger = logging.getLogger(__name__)

INJECTION_MARKERS: Sequence[str] = (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+.{0,30}(policy|rules|guardrails)",
    r"you\s+are\s+now\s+",
    r"sudo\s+rm\s+-rf",
    r"rm\s+-rf\s+/",
    r"curl[^|]{0,120}\|\s*(ba)?sh",
    r"chmod\s+777",
    r"/etc/(passwd|shadow)",
    r"exfiltrat(?:e|ion)",
    r"bypass\s+(the\s+)?(sandbox|policy|controls)",
)

_INJECTION_RES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in INJECTION_MARKERS)


def scan_text(text: str, agent_id: str = "auditor") -> List[Finding]:
    """Heuristic scan for unauthorized-logic indicators in free text."""
    findings: List[Finding] = []
    if not isinstance(text, str):
        return findings
    for regex in _INJECTION_RES:
        match = regex.search(text)
        if match:
            findings.append(
                Finding(
                    agent_id=agent_id,
                    severity=Severity.HIGH,
                    code="unauthorized-logic.marker",
                    summary=match.group(0)[:80],
                )
            )
    return findings


class BaseAgent(abc.ABC):
    """Identity, bus registration, error isolation and timing."""

    def __init__(self, identity: AgentIdentity, bus: MessageBus) -> None:
        self.identity = identity
        self.bus = bus
        bus.register(identity, self.handle)

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    def handle(self, envelope: Envelope) -> AgentResult:
        started = time.perf_counter()
        try:
            result = self.process(envelope)
        except Exception as exc:  # agents must never take down the bus
            logger.exception("agent %s failed", self.agent_id)
            result = AgentResult(
                agent_id=self.agent_id,
                success=False,
                verdict=Verdict.DENY,
                findings=[
                    Finding(
                        self.agent_id,
                        Severity.HIGH,
                        "agent.error",
                        f"{type(exc).__name__}: {exc}",
                    )
                ],
            )
        result.duration_s = round(time.perf_counter() - started, 6)
        return result

    @abc.abstractmethod
    def process(self, envelope: Envelope) -> AgentResult:
        """Handle one envelope and return a uniform result."""


class CoordinatorAgent(BaseAgent):
    """Turns a raw task into a normalized, ordered plan of steps.

    The whole task payload is scanned up front, so tasks carrying
    unauthorized-logic markers are blocked before any step runs.
    """

    def process(self, envelope: Envelope) -> AgentResult:
        task = dict(envelope.payload.get("task") or {})
        findings = scan_text(str(task), self.agent_id)
        raw_steps = task.get("steps") or [
            {"action": task.get("action", "echo"), "args": task.get("args", {})}
        ]
        plan = [
            {"action": str(spec.get("action", "")), "args": dict(spec.get("args", {}))}
            for spec in raw_steps
        ]
        return AgentResult(
            agent_id=self.agent_id,
            success=True,
            verdict=Verdict.DENY if findings else Verdict.ALLOW,
            output={"plan": plan},
            findings=findings,
        )


class PolicyRule:
    """Allow/deny rule matched against action names (first match wins)."""

    def __init__(self, pattern: str, verdict: Verdict, code: str, description: str = "") -> None:
        self.pattern = re.compile(pattern)
        self.verdict = verdict
        self.code = code
        self.description = description

    def match(self, action: str) -> bool:
        return self.pattern.fullmatch(action) is not None


DEFAULT_POLICY_RULES = (
    PolicyRule("echo|sum", Verdict.ALLOW, "policy.allowlist"),
    PolicyRule(".*", Verdict.DENY, "policy.default-deny", "Action not on the allowlist"),
)


class PolicyAgent(BaseAgent):
    """Renders allow/deny verdicts on every step before execution."""

    def __init__(
        self,
        identity: AgentIdentity,
        bus: MessageBus,
        rules: Optional[Sequence[PolicyRule]] = None,
    ) -> None:
        super().__init__(identity, bus)
        self.rules: Sequence[PolicyRule] = tuple(rules) if rules else DEFAULT_POLICY_RULES

    def decide(self, action: str) -> Verdict:
        for rule in self.rules:
            if rule.match(action):
                return rule.verdict
        return Verdict.DENY

    def process(self, envelope: Envelope) -> AgentResult:
        action = str(envelope.payload.get("action", ""))
        verdict = self.decide(action)
        findings = []
        if verdict is not Verdict.ALLOW:
            findings.append(
                Finding(
                    self.agent_id,
                    Severity.MEDIUM,
                    "policy.denied",
                    f"action '{action}' not allowed",
                )
            )
        return AgentResult(
            agent_id=self.agent_id,
            success=True,
            verdict=verdict,
            output={"action": action, "verdict": verdict.value},
            findings=findings,
        )


class ExecutorAgent(BaseAgent):
    """Runs allow-listed callables only - never eval or exec."""

    def __init__(
        self,
        identity: AgentIdentity,
        bus: MessageBus,
        actions: Optional[Dict[str, Callable[..., Any]]] = None,
    ) -> None:
        super().__init__(identity, bus)
        self._actions: Dict[str, Callable[..., Any]] = dict(actions or {})

    def register_action(self, name: str, func: Callable[..., Any]) -> None:
        self._actions[name] = func

    def process(self, envelope: Envelope) -> AgentResult:
        if str(envelope.payload.get("policy_verdict", "")) != Verdict.ALLOW.value:
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                verdict=Verdict.DENY,
                findings=[
                    Finding(
                        self.agent_id,
                        Severity.HIGH,
                        "executor.missing-approval",
                        "step reached the executor without a policy ALLOW verdict",
                    )
                ],
            )
        action = str(envelope.payload.get("action", ""))
        args = dict(envelope.payload.get("args") or {})
        func = self._actions.get(action)
        if func is None:
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                verdict=Verdict.DENY,
                findings=[
                    Finding(self.agent_id, Severity.MEDIUM, "executor.unknown-action", action)
                ],
            )
        output = func(**args) if args else func()
        return AgentResult(
            agent_id=self.agent_id,
            success=True,
            verdict=Verdict.ALLOW,
            output=output,
        )


class AuditorAgent(BaseAgent):
    """Reviews every intermediate payload for unauthorized logic."""

    def process(self, envelope: Envelope) -> AgentResult:
        findings = scan_text(str(envelope.payload), self.agent_id)
        return AgentResult(
            agent_id=self.agent_id,
            success=not findings,
            verdict=Verdict.ALLOW if not findings else Verdict.DENY,
            output={"audited": True, "clean": not findings},
            findings=findings,
        )


class VerifierAgent(BaseAgent):
    """Independent post-execution gate on outputs."""

    def process(self, envelope: Envelope) -> AgentResult:
        output = envelope.payload.get("output")
        findings = scan_text(str(output), self.agent_id)
        verified = bool(envelope.payload.get("executed", False)) and not findings
        return AgentResult(
            agent_id=self.agent_id,
            success=verified,
            verdict=Verdict.ALLOW if verified else Verdict.DENY,
            output={"verified": verified},
            findings=findings,
        )
