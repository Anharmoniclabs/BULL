"""Capability-checked message bus for the BULL multi-agent system.

Every message is delivered only to registered agents, every delivery is
written to an in-memory trace that can be streamed into bulldog's audit
layer, and a hop limit stops runaway forwarding loops. An optional host-owned
boundary guard can inspect both envelopes and handler results before they are
allowed to continue through the bus.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from .contracts import AgentIdentity, Envelope, TraceEvent

logger = logging.getLogger(__name__)

DEFAULT_MAX_HOPS = 8


class DeliveryError(RuntimeError):
    """Raised when a message cannot be delivered."""


class MessageBus:
    """Routes envelopes between registered agents with full tracing."""

    def __init__(self, max_hops: int = DEFAULT_MAX_HOPS) -> None:
        self._agents: Dict[str, AgentIdentity] = {}
        self._handlers: Dict[str, Callable[[Envelope], Any]] = {}
        self._trace: List[TraceEvent] = []
        self._lock = threading.Lock()
        self._boundary_guard: Optional[Callable[[str, Envelope, Any], None]] = None
        self.max_hops = max_hops

    def set_boundary_guard(
        self,
        guard: Optional[Callable[[str, Envelope, Any], None]],
    ) -> None:
        """Install one host-owned guard for envelope/result boundaries."""
        with self._lock:
            self._boundary_guard = guard

    def inspect_handler_exception(self, envelope: Envelope, error: BaseException) -> None:
        """Inspect an exception before an agent is allowed to log or summarize it.

        This gives the host boundary guard a chance to detect protected canary
        material in exception text/representation before any lower-trust logging
        path can expose it. Ordinary exceptions pass through this check and are
        then sanitized by ``BaseAgent``.
        """
        self._apply_boundary_guard("result", envelope, error)

    def register(
        self, identity: AgentIdentity, handler: Callable[[Envelope], Any]
    ) -> None:
        with self._lock:
            if identity.agent_id in self._handlers:
                raise DeliveryError(f"agent {identity.agent_id} already registered")
            self._agents[identity.agent_id] = identity
            self._handlers[identity.agent_id] = handler
        self._record(
            identity.agent_id,
            "registered",
            {
                "name": identity.name,
                "capabilities": sorted(cap.name for cap in identity.capabilities),
            },
        )

    def identity(self, agent_id: str) -> AgentIdentity:
        with self._lock:
            if agent_id not in self._agents:
                raise DeliveryError(f"unknown agent {agent_id}")
            return self._agents[agent_id]

    def agent_ids(self) -> List[str]:
        with self._lock:
            return list(self._agents)

    def deliver(self, envelope: Envelope) -> Any:
        """Deliver one envelope to exactly one recipient."""
        if envelope.hops > self.max_hops:
            self._record(
                envelope.sender,
                "dropped.loop-guard",
                {"hops": envelope.hops},
                envelope.trace_id,
            )
            raise DeliveryError(f"loop guard tripped after {envelope.hops} hops")

        self._apply_boundary_guard("envelope", envelope, None)

        with self._lock:
            handler = self._handlers.get(envelope.recipient)
        if handler is None:
            raise DeliveryError(f"unknown recipient {envelope.recipient}")
        self._record(
            envelope.sender,
            "deliver",
            {"to": envelope.recipient, "type": envelope.message_type},
            envelope.trace_id,
        )
        result = handler(envelope)
        self._apply_boundary_guard("result", envelope, result)
        self._record(
            envelope.recipient,
            "handled",
            {"type": envelope.message_type},
            envelope.trace_id,
        )
        return result

    def broadcast(
        self, envelope: Envelope, capability: Optional[str] = None
    ) -> List[Any]:
        """Send to every agent holding ``capability`` (all agents if None)."""
        with self._lock:
            targets = [
                agent_id
                for agent_id, ident in self._agents.items()
                if capability is None
                or any(cap.name == capability for cap in ident.capabilities)
            ]
        results: List[Any] = []
        for target in targets:
            forwarded = envelope.forwarded(
                target, envelope.message_type, dict(envelope.payload)
            )
            results.append(self.deliver(forwarded))
        return results

    def trace(self, trace_id: Optional[str] = None) -> List[TraceEvent]:
        with self._lock:
            events = list(self._trace)
        if trace_id is None:
            return events
        return [event for event in events if event.trace_id == trace_id]

    def _apply_boundary_guard(
        self,
        phase: str,
        envelope: Envelope,
        result: Any,
    ) -> None:
        with self._lock:
            guard = self._boundary_guard
        if guard is None:
            return
        try:
            guard(phase, envelope, result)
        except Exception as exc:
            # Never put exception text in the bus trace: a security guard may
            # intentionally protect a secret marker. Record only type/stage.
            self._record(
                envelope.sender,
                "dropped.boundary-guard",
                {
                    "stage": phase,
                    "error_type": type(exc).__name__,
                },
                envelope.trace_id,
            )
            raise

    def _record(
        self,
        agent_id: str,
        event: str,
        detail: Dict[str, Any],
        trace_id: str = "",
    ) -> None:
        with self._lock:
            self._trace.append(
                TraceEvent(trace_id=trace_id, agent_id=agent_id, event=event, detail=detail)
            )
        logger.debug("bus event %s by %s: %s", event, agent_id, detail)
