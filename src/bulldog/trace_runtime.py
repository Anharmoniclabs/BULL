from __future__ import annotations

from dataclasses import dataclass, field

from .trace_model import (
    BullTraceState,
    TraceEvent,
    TraceViolation,
    apply_transition,
)


@dataclass
class RuntimeTraceVerifier:
    """
    Online verifier for BULL runtime transitions.

    Every emitted event must be legal under the same
    transition vocabulary used by the formal model.
    """

    state: BullTraceState = field(
        default_factory=BullTraceState
    )

    events: list[TraceEvent] = field(
        default_factory=list
    )

    def emit(
        self,
        transition: str,
        **data,
    ) -> BullTraceState:

        event = TraceEvent(
            transition=transition,
            data=dict(data),
        )

        next_state = apply_transition(
            self.state,
            event,
        )

        self.events.append(
            event
        )

        self.state = (
            next_state
        )

        return self.state

    def snapshot(
        self,
    ) -> BullTraceState:

        return self.state

    def reset(
        self,
        *,
        parent_has_capability: bool = False,
    ) -> None:

        self.state = BullTraceState(
            parent_has_capability=(
                parent_has_capability
            )
        )

        self.events.clear()
