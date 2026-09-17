"""Built-in agents for the BULL multi-agent system.

Pipeline: Coordinator -> Policy -> Executor -> Auditor + Verifier.
Nothing executes unless the policy agent allows it, and no result is
accepted until the auditor and the independent verifier sign off -
the multi-agent expression of BULL's core mission.

The scanner is hardened against red-team obfuscation: text is NFKC
normalized, zero-width and bidi control characters are replaced with
spaces, common Cyrillic lookalikes are mapped to ASCII, whitespace runs
are collapsed, and base64-looking tokens are decoded and rescanned, so
homoglyphs, zero-width splits, spacing tricks and encoded payloads do
not slip past the markers. The executor additionally requires a
one-time approval token minted by the policy agent, so a forged
policy_verdict string in a bus envelope can no longer reach execution.
"""

from __future__ import annotations

import abc
import base64
import binascii
import logging
import re
import time
import unicodedata
import uuid
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
    r"sudo\s+rm\s*-\s*rf",
    r"rm\s*-\s*rf\s+/",
    r"(curl|wget)[^|]{0,120}\|\s*(ba|z)?sh\b",
    r"\|\s*(ba|z)?sh\b",
    r"chmod\s+777",
    r"/etc/(passwd|shadow)",
    r"exfiltrat(?:e|ion)",
    r"bypass\s+(the\s+)?(sandbox|policy|controls)",
)

_INJECTION_RES = tuple(re.compile(pattern, re.IGNORECASE) for pattern in INJECTION_MARKERS)

# Zero-width and bidi control characters are replaced with spaces so
# splitting a marker with them ("ignore<ZWSP>all") cannot glue words
# together after removal.
ZERO_WIDTH = "\u200b\u200c\u200d\u200e\u200f\u2060\u2061\ufeff\u00ad\u180e"

# Common Cyrillic confusables mapped to their ASCII lookalikes so
# homoglyph substitution ("\u0456gnore") cannot evade the markers.
CONFUSABLES = str.maketrans(
    {
        "\u0456": "i",
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0455": "s",
        "\u0445": "x",
        "\u0501": "d",
        "\u051b": "q",
        "\u051d": "w",
        "\u04ae": "y",
    }
)

MAX_SCAN_CHARS = 65536
MAX_PLAN_STEPS = 64
MAX_TASK_CHARS = 131072

_B64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def normalize_text(text: str) -> str:
    """Defeat obfuscation before scanning.

    Applies NFKC normalization, replaces zero-width/bidi controls with
    spaces, maps common lookalikes to ASCII and collapses whitespace
    runs so spacing tricks like ``rm - rf /`` do not split a marker.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(str.maketrans(ZERO_WIDTH, " " * len(ZERO_WIDTH)))
    text = text.translate(CONFUSABLES)
    text = re.sub(r"\s+", " ", text)
    return text


def scan_text(text: str, agent_id: str = "auditor") -> List[Finding]:
    """Heuristic scan for unauthorized-logic indicators in free text.

    The text is normalized first (homoglyphs, zero-width characters,
    spacing tricks), and base64-looking tokens are decoded and
    rescanned so encoded payloads cannot slip past the markers.
    """
    findings: List[Finding] = []
    if not isinstance(text, str):
        return findings
    normalized = normalize_text(text[:MAX_SCAN_CHARS])
    for regex in _INJECTION_RES:
        match = regex.search(normalized)
        if match:
            findings.append(
                Finding(
                    agent_id=agent_id,
                    severity=Severity.HIGH,
                    code="unauthorized-logic.marker",
                    summary=match.group(0)[:80],
                )
            )
    for token in _B64_TOKEN.findall(normalized):
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        for regex in _INJECTION_RES:
            match = regex.search(normalize_text(decoded))
            if match:
                findings.append(
                    Finding(
                        agent_id=agent_id,
                        severity=Severity.HIGH,
                        code="unauthorized-logic.encoded",
                        summary=f"base64-decoded: {match.group(0)[:60]}",
                    )
                )
                break
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
    """Turns a raw task into a normalized, size-capped plan of steps.

    The whole task payload is scanned up front, so tasks carrying
    unauthorized-logic markers are blocked before any step runs. Plans
    larger than ``MAX_PLAN_STEPS`` steps or task payloads larger than
    ``MAX_TASK_CHARS`` characters are denied, closing the plan-bomb and
    text-bomb denial-of-service vectors.
    """

    def process(self, envelope: Envelope) -> AgentResult:
        task = dict(envelope.payload.get("task") or {})
        raw = str(task)
        findings: List[Finding] = []
        if len(raw) > MAX_TASK_CHARS:
            findings.append(
                Finding(
                    self.agent_id,
                    Severity.MEDIUM,
                    "input.too-large",
                    f"task payload exceeds {MAX_TASK_CHARS} characters",
                )
            )
        findings.extend(scan_text(raw, self.agent_id))
        raw_steps = task.get("steps") or [
            {"action": task.get("action", "echo"), "args": task.get("args", {})}
        ]
        if len(raw_steps) > MAX_PLAN_STEPS:
            findings.append(
                Finding(
                    self.agent_id,
                    Severity.MEDIUM,
                    "input.plan-too-large",
                    f"plan has {len(raw_steps)} steps, limit is {MAX_PLAN_STEPS}",
                )
            )
        plan = [
            {"action": str(spec.get("action", "")), "args": dict(spec.get("args", {}))}
            for spec in raw_steps[:MAX_PLAN_STEPS]
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
    """Renders allow/deny verdicts and mints one-time approval tokens.

    The executor only runs a step when presented with an unconsumed
    token minted by this agent, so a forged ``policy_verdict`` string
    in a bus envelope is no longer sufficient to reach execution.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        bus: MessageBus,
        rules: Optional[Sequence[PolicyRule]] = None,
    ) -> None:
        super().__init__(identity, bus)
        self.rules: Sequence[PolicyRule] = tuple(rules) if rules else DEFAULT_POLICY_RULES
        self._tokens: Dict[str, str] = {}

    def decide(self, action: str) -> Verdict:
        for rule in self.rules:
            if rule.match(action):
                return rule.verdict
        return Verdict.DENY

    def consume(self, token: Any, action: str) -> bool:
        """Atomically consume a one-time approval token."""
        if not isinstance(token, str) or self._tokens.get(token) != action:
            return False
        del self._tokens[token]
        return True

    def process(self, envelope: Envelope) -> AgentResult:
        action = str(envelope.payload.get("action", ""))
        verdict = self.decide(action)
        findings: List[Finding] = []
        output: Dict[str, Any] = {"action": action, "verdict": verdict.value}
        if verdict is Verdict.ALLOW:
            token = uuid.uuid4().hex
            self._tokens[token] = action
            output["token"] = token
        else:
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
            output=output,
            findings=findings,
        )


class ExecutorAgent(BaseAgent):
    """Runs allow-listed callables behind a one-time approval token."""

    def __init__(
        self,
        identity: AgentIdentity,
        bus: MessageBus,
        actions: Optional[Dict[str, Callable[..., Any]]] = None,
        approver: Optional[PolicyAgent] = None,
    ) -> None:
        super().__init__(identity, bus)
        self._actions: Dict[str, Callable[..., Any]] = dict(actions or {})
        self._approver = approver

    def register_action(self, name: str, func: Callable[..., Any]) -> None:
        self._actions[name] = func

    def process(self, envelope: Envelope) -> AgentResult:
        action = str(envelope.payload.get("action", ""))
        token = envelope.payload.get("approval_token")
        if self._approver is None or not self._approver.consume(token, action):
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                verdict=Verdict.DENY,
                findings=[
                    Finding(
                        self.agent_id,
                        Severity.HIGH,
                        "executor.missing-approval",
                        "step reached the executor without a valid one-time approval token",
                    )
                ],
            )
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
