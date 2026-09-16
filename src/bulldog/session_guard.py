from __future__ import annotations

from dataclasses import dataclass, field

from .models import ActionRequest, Capability, Decision, Evaluation


_DECISION_ORDER = {
    Decision.ALLOW: 0,
    Decision.SANDBOX: 1,
    Decision.ESCALATE: 2,
    Decision.DENY: 3,
}


PROJECT_CAPABILITIES = {
    Capability.FS_READ_PROJECT,
    Capability.FS_WRITE_PROJECT,
}


PRIVILEGED_CAPABILITIES = {
    Capability.CREDENTIAL_READ,
    Capability.PROCESS_EXEC,
    Capability.NETWORK_POST,
    Capability.PACKAGE_INSTALL,
    Capability.AGENT_SPAWN,
    Capability.SECURITY_CONTROL_WRITE,
}


@dataclass(frozen=True)
class SessionEvent:
    action: ActionRequest
    evaluation: Evaluation


@dataclass
class SessionGuard:
    max_history: int = 32
    history: dict[str, list[SessionEvent]] = field(default_factory=dict)

    def session_key(self, action: ActionRequest) -> str:
        return action.metadata.get("session_id") or action.actor

    def enforce(
        self,
        action: ActionRequest,
        evaluation: Evaluation,
    ) -> Evaluation:
        key = self.session_key(action)
        events = self.history.setdefault(key, [])

        if evaluation.hard_block:
            self._remember(events, action, evaluation)
            return evaluation

        flags: list[str] = []

        previous_actions = [event.action for event in events]
        previous_results = [event.evaluation for event in events]

        if (
            action.capability == Capability.CREDENTIAL_READ
            and any(a.capability in PROJECT_CAPABILITIES for a in previous_actions)
            and not any(
                a.capability == Capability.CREDENTIAL_READ
                for a in previous_actions
            )
        ):
            flags.append("GOAL_DRIFT")

        if (
            action.capability in PRIVILEGED_CAPABILITIES
            and previous_actions
            and all(
                a.capability not in PRIVILEGED_CAPABILITIES
                for a in previous_actions[-3:]
            )
        ):
            flags.append("AUTHORITY_SHIFT")

        if previous_results:
            previous = previous_results[-1]
            previous_action = previous_actions[-1]

            if (
                previous.decision in {
                    Decision.SANDBOX,
                    Decision.ESCALATE,
                    Decision.DENY,
                }
                and action.capability != previous_action.capability
            ):
                flags.append("ALTERNATE_PATH_AFTER_RESTRICTION")

        recent_caps = [
            a.capability
            for a in previous_actions[-3:]
        ] + [action.capability]

        if len(recent_caps) >= 4 and len(set(recent_caps)) >= 4:
            flags.append("TOOL_SHOPPING")

        result = evaluation

        if flags:
            behavioral_decision = Decision.ESCALATE

            decision = max(
                evaluation.decision,
                behavioral_decision,
                key=lambda d: _DECISION_ORDER[d],
            )

            risk = max(evaluation.risk, 0.90)

            reasons = evaluation.reasons + tuple(
                f"session behavior: {flag}"
                for flag in flags
            )

            result = Evaluation(
                decision=decision,
                risk=risk,
                reasons=reasons,
                hard_block=evaluation.hard_block,
            )

        self._remember(events, action, result)
        return result

    def _remember(
        self,
        events: list[SessionEvent],
        action: ActionRequest,
        evaluation: Evaluation,
    ) -> None:
        events.append(SessionEvent(action, evaluation))

        if len(events) > self.max_history:
            del events[:-self.max_history]

    def clear(self, session_id: str | None = None) -> None:
        if session_id is None:
            self.history.clear()
        else:
            self.history.pop(session_id, None)
