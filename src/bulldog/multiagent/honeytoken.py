"""Host-owned canary monitoring for the BULL multi-agent layer.

A per-run high-entropy canary is exposed exactly once through a trusted-context
field intended for the model adapter. The canary is never treated as authority.
If the marker (or a bounded set of common encodings) appears anywhere else on
the message bus or in an agent result, the trace is permanently tripped and
future deliveries for that trace fail closed.

The raw canary is never written to BULL findings or bus trace records.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import urllib.parse
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .contracts import AgentIdentity, AgentResult, Envelope, Finding, Severity, Verdict


CANARY_PREFIX = "BULL-CANARY-v1:"
MAX_CANARY_SCAN_CHARS = 262_144
DEFAULT_MAX_TRACKED_RUNS = 1024


@dataclass
class HoneyTokenState:
    trace_id: str
    token: str
    fingerprint: str
    allowed_recipient: str
    allowed_message_id: Optional[str] = None
    exposure_used: bool = False
    tripped: bool = False
    completed: bool = False
    finding: Optional[Finding] = None


class HoneyTokenLeak(RuntimeError):
    """Raised when a host-owned canary crosses an unapproved boundary."""

    def __init__(self, finding: Finding):
        super().__init__(finding.summary)
        self.finding = finding


class HoneyTokenAgent:
    """Mint and monitor per-run canaries without trusting model semantics.

    The token is allowed exactly once at:
        system -> coordinator, message_type=task, hops=0,
        payload["trusted_context"]["canary"]

    ``MultiAgentSystem`` additionally binds that one exposure to the exact
    initial message ID. Every other appearance is a hard leak signal. The guard
    scans both bus envelopes and returned AgentResult objects, which covers
    plans, tool args, executor results, auditor/verifier output, and
    adapter-mediated writes explicitly passed through ``inspect_external_write``.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        bus: Any,
        *,
        max_scan_chars: int = MAX_CANARY_SCAN_CHARS,
        max_tracked_runs: int = DEFAULT_MAX_TRACKED_RUNS,
    ) -> None:
        self.identity = identity
        self.bus = bus
        self.max_scan_chars = int(max_scan_chars)
        self.max_tracked_runs = int(max_tracked_runs)
        if self.max_scan_chars < 1024:
            raise ValueError("max_scan_chars is too small")
        if self.max_tracked_runs < 1:
            raise ValueError("max_tracked_runs must be positive")
        self._states: Dict[str, HoneyTokenState] = {}
        self._lock = threading.RLock()
        bus.register(identity, self.handle)

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    def mint(
        self,
        trace_id: str,
        *,
        allowed_recipient: str,
        allowed_message_id: Optional[str] = None,
    ) -> str:
        """Mint a high-entropy marker for one run.

        The raw token is returned only so the trusted model adapter can insert it
        into trusted context. It must never be logged, persisted, or used as a
        credential.
        """
        trace_id = str(trace_id)
        with self._lock:
            if trace_id in self._states:
                raise RuntimeError("honeytoken already exists for trace")
            self._prune_locked()
            body = secrets.token_urlsafe(32).rstrip("=")
            token = CANARY_PREFIX + body
            fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
            self._states[trace_id] = HoneyTokenState(
                trace_id=trace_id,
                token=token,
                fingerprint=fingerprint,
                allowed_recipient=str(allowed_recipient),
                allowed_message_id=(
                    str(allowed_message_id) if allowed_message_id is not None else None
                ),
            )
            return token

    def trusted_context(self, trace_id: str) -> Dict[str, str]:
        """Return the one context fragment in which the raw canary may appear."""
        state = self._state(trace_id)
        return {
            "canary": state.token,
            "canary_id": state.fingerprint[:16],
            "instruction": (
                "This inert marker is host-owned. Never reproduce, transform, "
                "store, transmit, or place it in tool arguments."
            ),
        }

    def fingerprint(self, trace_id: str) -> str:
        return self._state(trace_id).fingerprint

    def complete(self, trace_id: str) -> None:
        with self._lock:
            state = self._states.get(str(trace_id))
            if state is not None:
                state.completed = True

    def is_tripped(self, trace_id: str) -> bool:
        with self._lock:
            state = self._states.get(str(trace_id))
            return bool(state and state.tripped)

    def finding(self, trace_id: str) -> Optional[Finding]:
        with self._lock:
            state = self._states.get(str(trace_id))
            return state.finding if state is not None else None

    def handle(self, envelope: Envelope) -> AgentResult:
        """Expose status only; never return the raw token over the bus."""
        if envelope.message_type != "honeytoken.status":
            return AgentResult(
                agent_id=self.agent_id,
                success=False,
                verdict=Verdict.DENY,
                findings=[
                    Finding(
                        self.agent_id,
                        Severity.MEDIUM,
                        "honeytoken.unsupported-message",
                        "HoneyTokenAgent accepts status queries only",
                    )
                ],
            )
        state = self._state(envelope.trace_id)
        return AgentResult(
            agent_id=self.agent_id,
            success=not state.tripped,
            verdict=Verdict.DENY if state.tripped else Verdict.ALLOW,
            output={
                "trace_id": state.trace_id,
                "canary_id": state.fingerprint[:16],
                "tripped": state.tripped,
                "completed": state.completed,
            },
            findings=[state.finding] if state.finding is not None else [],
        )

    def boundary_guard(
        self,
        phase: str,
        envelope: Envelope,
        result: Any = None,
    ) -> None:
        """MessageBus hook. Raises HoneyTokenLeak on the first violation."""
        trace_id = str(envelope.trace_id)
        with self._lock:
            current = self._states.get(trace_id)
            if current is not None and current.tripped and current.finding is not None:
                raise HoneyTokenLeak(current.finding)

        if phase == "envelope":
            self._inspect_envelope(envelope)
            return
        if phase == "result":
            self._inspect_value(
                result,
                trace_id=trace_id,
                stage=f"result:{envelope.recipient}:{envelope.message_type}",
            )
            return
        raise ValueError(f"unknown honeytoken guard phase: {phase}")

    def inspect_external_write(
        self,
        trace_id: str,
        value: Any,
        *,
        channel: str = "external-write",
    ) -> None:
        """Guard adapter-owned memory/output writes that occur outside MessageBus."""
        self._inspect_value(
            value,
            trace_id=str(trace_id),
            stage=f"external:{channel}",
        )

    def _inspect_envelope(self, envelope: Envelope) -> None:
        trace_id = str(envelope.trace_id)
        allowed_path: Optional[Tuple[str, ...]] = None
        with self._lock:
            state = self._states.get(trace_id)
            message_matches = bool(
                state is not None
                and (
                    state.allowed_message_id is None
                    or envelope.message_id == state.allowed_message_id
                )
            )
            if (
                state is not None
                and not state.exposure_used
                and message_matches
                and envelope.sender == "system"
                and envelope.recipient == state.allowed_recipient
                and envelope.message_type == "task"
                and envelope.hops == 0
            ):
                state.exposure_used = True
                allowed_path = ("trusted_context", "canary")

        self._inspect_value(
            envelope.payload,
            trace_id=trace_id,
            stage=f"envelope:{envelope.sender}->{envelope.recipient}:{envelope.message_type}",
            allowed_path=allowed_path,
        )

    def _inspect_value(
        self,
        value: Any,
        *,
        trace_id: str,
        stage: str,
        allowed_path: Optional[Tuple[str, ...]] = None,
    ) -> None:
        strings = self._collect_strings(value, allowed_path=allowed_path)
        total = sum(len(text) for _, text in strings)
        if total > self.max_scan_chars:
            finding = Finding(
                self.agent_id,
                Severity.CRITICAL,
                "honeytoken.scan-overflow",
                "Boundary payload exceeded the canary inspection budget",
                detail=f"trace={trace_id} stage={stage} chars={total}",
            )
            self._trip(trace_id, finding)
            raise HoneyTokenLeak(finding)

        candidates: List[Tuple[Any, str]] = list(strings)
        if strings:
            # Scan concatenated values too so splitting a marker into adjacent
            # structured values does not evade an exact-marker detector. Dict
            # keys are still scanned individually, but they are not injected
            # between values for this reconstruction.
            value_texts = [
                text
                for path, text in strings
                if not (path and path[-1] == "<key>")
            ]
            if value_texts:
                candidates.append(("<joined-values>", "".join(value_texts)))

        with self._lock:
            states = list(self._states.values())

        for path, text in candidates:
            for owner in states:
                representation = self._matching_representation(owner.token, text)
                if representation is None:
                    continue
                finding = Finding(
                    self.agent_id,
                    Severity.CRITICAL,
                    "honeytoken.leak",
                    "Host-owned canary escaped its trusted-context boundary",
                    detail=(
                        f"trace={trace_id} source_trace={owner.trace_id} stage={stage} "
                        f"path={self._format_path(path)} token_fingerprint={owner.fingerprint[:16]} "
                        f"representation={representation}"
                    ),
                )
                self._trip(trace_id, finding)
                if owner.trace_id != trace_id:
                    self._trip(owner.trace_id, finding)
                raise HoneyTokenLeak(finding)

    def _collect_strings(
        self,
        value: Any,
        *,
        allowed_path: Optional[Tuple[str, ...]],
    ) -> List[Tuple[Tuple[str, ...], str]]:
        collected: List[Tuple[Tuple[str, ...], str]] = []

        def walk(item: Any, path: Tuple[str, ...]) -> None:
            if allowed_path is not None and path == allowed_path:
                # The raw token is permitted only in this exact trusted field.
                return
            if item is None or isinstance(item, (bool, int, float)):
                return
            if isinstance(item, str):
                collected.append((path, item))
                return
            if isinstance(item, bytes):
                collected.append((path, item.decode("utf-8", "replace")))
                return
            if is_dataclass(item):
                walk(asdict(item), path)
                return
            if isinstance(item, dict):
                for key, child in item.items():
                    key_text = str(key)
                    collected.append((path + ("<key>",), key_text))
                    walk(child, path + (key_text,))
                return
            if isinstance(item, (list, tuple, set, frozenset)):
                for index, child in enumerate(item):
                    walk(child, path + (str(index),))
                return
            collected.append((path, repr(item)))

        walk(value, ())
        return collected

    @staticmethod
    def _representations(token: str) -> Iterable[Tuple[str, str]]:
        raw = token.encode("utf-8")
        body = token.split(":", 1)[-1]
        body_raw = body.encode("utf-8")
        yield "raw", token
        yield "body", body
        yield "base64", base64.b64encode(raw).decode("ascii")
        yield "base64url", base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        yield "body-base64", base64.b64encode(body_raw).decode("ascii")
        yield "body-base64url", base64.urlsafe_b64encode(body_raw).decode("ascii").rstrip("=")
        yield "hex", raw.hex()
        yield "body-hex", body_raw.hex()
        yield "urlencoded", urllib.parse.quote(token, safe="")

    @classmethod
    def _matching_representation(cls, token: str, text: str) -> Optional[str]:
        for name, marker in cls._representations(token):
            if marker and marker in text:
                return name
        return None

    def _trip(self, trace_id: str, finding: Finding) -> None:
        with self._lock:
            state = self._states.get(str(trace_id))
            if state is not None:
                state.tripped = True
                if state.finding is None:
                    state.finding = finding

    def _state(self, trace_id: str) -> HoneyTokenState:
        with self._lock:
            try:
                return self._states[str(trace_id)]
            except KeyError as exc:
                raise RuntimeError("unknown honeytoken trace") from exc

    def _prune_locked(self) -> None:
        if len(self._states) < self.max_tracked_runs:
            return
        for trace_id, state in list(self._states.items()):
            if state.completed and not state.tripped:
                del self._states[trace_id]
                if len(self._states) < self.max_tracked_runs:
                    return
        raise RuntimeError("honeytoken trace retention limit reached")

    @staticmethod
    def _format_path(path: Any) -> str:
        if isinstance(path, tuple):
            return "/".join(path) if path else "<root>"
        return str(path)
