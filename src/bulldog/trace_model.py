from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable


class TraceViolation(RuntimeError):
    pass


DECISIONS = {
    "PENDING",
    "ALLOW",
    "SANDBOX",
    "ESCALATE",
    "DENY",
}


PHASES = {
    "start",
    "evaluated",
    "scanned",
    "blocked",
    "review",
    "executed",
}


EXECUTABLE_DECISIONS = {
    "ALLOW",
    "SANDBOX",
}


TRANSITIONS = {
    "Evaluate",
    "ScanClean",
    "ScanMalware",
    "BlockMalware",
    "Execute",
    "ResolveDeny",
    "ResolveEscalate",
    "GrantChildCapability",
    "GrantSecret",
    "ReturnSecret",
    "GrantBroker",
    "BrokerEgress",
}


@dataclass(frozen=True)
class BullTraceState:
    phase: str = "start"
    decision: str = "PENDING"

    scanned: bool = False
    malware_clean: bool = False

    executed: bool = False
    sandboxed: bool = False
    seccomp: bool = False

    review_required: bool = False

    parent_has_capability: bool = False
    child_has_capability: bool = False

    secret_granted: bool = False
    secret_returned: bool = False

    broker_granted: bool = False
    egress_occurred: bool = False

    direct_network: bool = False


@dataclass(frozen=True)
class TraceEvent:
    transition: str
    data: dict


def _fail(message: str) -> None:
    raise TraceViolation(message)


def validate_invariants(
    state: BullTraceState,
) -> None:

    if state.phase not in PHASES:
        _fail(
            f"invalid phase: {state.phase}"
        )

    if state.decision not in DECISIONS:
        _fail(
            f"invalid decision: {state.decision}"
        )

    # DENY never executes.
    if (
        state.decision == "DENY"
        and state.executed
    ):
        _fail(
            "DENY state executed"
        )

    # ESCALATE never executes.
    if (
        state.decision == "ESCALATE"
        and state.executed
    ):
        _fail(
            "ESCALATE state executed"
        )

    # Execution requires approved decision.
    if (
        state.executed
        and state.decision
        not in EXECUTABLE_DECISIONS
    ):
        _fail(
            "execution occurred without ALLOW/SANDBOX"
        )

    # Execution requires clean malware scan.
    if state.executed and not (
        state.scanned
        and state.malware_clean
    ):
        _fail(
            "execution occurred without clean malware scan"
        )

    # Execution always sandboxed.
    if (
        state.executed
        and not state.sandboxed
    ):
        _fail(
            "executed workload was not sandboxed"
        )

    # Execution always seccomp-protected.
    if (
        state.executed
        and not state.seccomp
    ):
        _fail(
            "executed workload lacked seccomp"
        )

    # Malware never executes.
    if (
        state.scanned
        and not state.malware_clean
        and state.executed
    ):
        _fail(
            "malware-detected workload executed"
        )

    # Child authority <= parent authority.
    if (
        state.child_has_capability
        and not state.parent_has_capability
    ):
        _fail(
            "child authority exceeded parent authority"
        )

    # Secret return requires grant.
    if (
        state.secret_returned
        and not state.secret_granted
    ):
        _fail(
            "secret returned without grant"
        )

    # Brokered egress requires grant.
    if (
        state.egress_occurred
        and not state.broker_granted
    ):
        _fail(
            "egress occurred without broker grant"
        )

    # Direct network must always remain off.
    if state.direct_network:
        _fail(
            "direct network became enabled"
        )

    # Review state corresponds to escalation.
    if state.phase == "review":

        if not (
            state.decision == "ESCALATE"
            and state.review_required
        ):
            _fail(
                "review phase does not correspond to ESCALATE"
            )


def apply_transition(
    state: BullTraceState,
    event: TraceEvent,
) -> BullTraceState:

    name = event.transition
    data = dict(
        event.data
    )

    if name not in TRANSITIONS:
        _fail(
            f"unknown transition: {name}"
        )


    # =====================================================================
    # Evaluate
    # =====================================================================

    if name == "Evaluate":

        if state.phase != "start":
            _fail(
                "Evaluate requires start phase"
            )

        decision = str(
            data.get(
                "decision",
                "",
            )
        )

        if decision not in {
            "ALLOW",
            "SANDBOX",
            "ESCALATE",
            "DENY",
        }:
            _fail(
                f"invalid Evaluate decision: {decision}"
            )

        next_state = replace(
            state,
            phase="evaluated",
            decision=decision,
        )


    # =====================================================================
    # ScanClean
    # =====================================================================

    elif name == "ScanClean":

        if not (
            state.phase == "evaluated"
            and state.decision
            in EXECUTABLE_DECISIONS
        ):
            _fail(
                "ScanClean illegal from current state"
            )

        next_state = replace(
            state,
            phase="scanned",
            scanned=True,
            malware_clean=True,
        )


    # =====================================================================
    # ScanMalware
    # =====================================================================

    elif name == "ScanMalware":

        if not (
            state.phase == "evaluated"
            and state.decision
            in EXECUTABLE_DECISIONS
        ):
            _fail(
                "ScanMalware illegal from current state"
            )

        next_state = replace(
            state,
            phase="scanned",
            scanned=True,
            malware_clean=False,
        )


    # =====================================================================
    # BlockMalware
    # =====================================================================

    elif name == "BlockMalware":

        if not (
            state.phase == "scanned"
            and state.scanned
            and not state.malware_clean
        ):
            _fail(
                "BlockMalware illegal from current state"
            )

        next_state = replace(
            state,
            phase="blocked",
        )


    # =====================================================================
    # Execute
    # =====================================================================

    elif name == "Execute":

        if not (
            state.phase == "scanned"
            and state.decision
            in EXECUTABLE_DECISIONS
            and state.scanned
            and state.malware_clean
            and not state.executed
        ):
            _fail(
                "Execute illegal from current state"
            )

        sandboxed = bool(
            data.get(
                "sandboxed",
                False,
            )
        )

        seccomp = bool(
            data.get(
                "seccomp",
                False,
            )
        )

        next_state = replace(
            state,
            phase="executed",
            executed=True,
            sandboxed=sandboxed,
            seccomp=seccomp,
        )


    # =====================================================================
    # ResolveDeny
    # =====================================================================

    elif name == "ResolveDeny":

        if not (
            state.phase == "evaluated"
            and state.decision == "DENY"
        ):
            _fail(
                "ResolveDeny illegal from current state"
            )

        next_state = replace(
            state,
            phase="blocked",
        )


    # =====================================================================
    # ResolveEscalate
    # =====================================================================

    elif name == "ResolveEscalate":

        if not (
            state.phase == "evaluated"
            and state.decision == "ESCALATE"
        ):
            _fail(
                "ResolveEscalate illegal from current state"
            )

        next_state = replace(
            state,
            phase="review",
            review_required=True,
        )


    # =====================================================================
    # GrantChildCapability
    # =====================================================================

    elif name == "GrantChildCapability":

        if not (
            state.parent_has_capability
            and not state.child_has_capability
        ):
            _fail(
                "child capability grant exceeds parent authority"
            )

        next_state = replace(
            state,
            child_has_capability=True,
        )


    # =====================================================================
    # GrantSecret
    # =====================================================================

    elif name == "GrantSecret":

        if state.secret_granted:
            _fail(
                "secret grant already exists"
            )

        next_state = replace(
            state,
            secret_granted=True,
        )


    # =====================================================================
    # ReturnSecret
    # =====================================================================

    elif name == "ReturnSecret":

        if not (
            state.secret_granted
            and not state.secret_returned
        ):
            _fail(
                "ReturnSecret requires active grant"
            )

        next_state = replace(
            state,
            secret_returned=True,
        )


    # =====================================================================
    # GrantBroker
    # =====================================================================

    elif name == "GrantBroker":

        if state.broker_granted:
            _fail(
                "broker grant already exists"
            )

        next_state = replace(
            state,
            broker_granted=True,
        )


    # =====================================================================
    # BrokerEgress
    # =====================================================================

    elif name == "BrokerEgress":

        if not (
            state.broker_granted
            and not state.egress_occurred
        ):
            _fail(
                "BrokerEgress requires broker grant"
            )

        next_state = replace(
            state,
            egress_occurred=True,
        )


    else:
        raise AssertionError(
            name
        )


    validate_invariants(
        next_state
    )

    return next_state


def verify_trace(
    events: Iterable[TraceEvent],
    *,
    initial: BullTraceState | None = None,
) -> BullTraceState:

    state = (
        initial
        if initial is not None
        else BullTraceState()
    )

    validate_invariants(
        state
    )

    for index, event in enumerate(
        events
    ):

        try:

            state = apply_transition(
                state,
                event,
            )

        except TraceViolation as exc:

            raise TraceViolation(
                f"trace event {index} "
                f"({event.transition}) violated model: {exc}"
            ) from exc

    return state
