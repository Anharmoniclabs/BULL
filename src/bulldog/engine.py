from __future__ import annotations

from .advisory import AdvisoryModel, NullAdvisoryModel
from .audit import AuditLedger
from .models import ActionRequest, Decision, Evaluation
from .policy import DeterministicPolicy


_DECISION_ORDER = {
    Decision.ALLOW: 0,
    Decision.SANDBOX: 1,
    Decision.ESCALATE: 2,
    Decision.DENY: 3,
}


class BulldogEngine:
    def __init__(
        self,
        policy: DeterministicPolicy | None = None,
        advisory: AdvisoryModel | None = None,
        ledger: AuditLedger | None = None,
    ):
        self.policy = policy or DeterministicPolicy()
        self.advisory = advisory or NullAdvisoryModel()
        self.ledger = ledger

    def evaluate(self, action: ActionRequest) -> Evaluation:
        hard = self.policy.evaluate(action)
        if hard.hard_block:
            result = hard
        else:
            advisory = self.advisory.evaluate(action)
            decision = max(
                (hard.decision, advisory.recommendation),
                key=lambda d: _DECISION_ORDER[d],
            )
            risk = max(hard.risk, min(max(advisory.risk, 0.0), 1.0))
            reasons = hard.reasons
            if advisory.reason and advisory.reason != "no advisory model configured":
                reasons = reasons + (f"advisory: {advisory.reason}",)
            result = Evaluation(decision, risk, reasons, hard_block=False)

        if self.ledger is not None:
            self.ledger.append(action, result)
        return result
