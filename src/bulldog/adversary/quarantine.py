"""Per-finding quarantine: lock each attacker into its own environment.

Severity of the attacker's findings selects the isolation profile. In
production the cell maps onto bulldog's namespace sandbox (strict
seccomp + landlock); inside the capture layer it is the bookkeeping
that drives that decision.
"""

from __future__ import annotations

import uuid
from typing import List, Sequence

from .contracts import AttackerRecord, IsolationProfile, QuarantineCell

HIGH_SEVERITY_FINDINGS = frozenset({
    "unauthorized-logic.marker",
    "unauthorized-logic.encoded",
    "executor.missing-approval",
    "input.too-large",
    "input.plan-too-large",
    "policy.denied",
})


class QuarantineManager:
    """Assigns each attacker a locked cell sized to its findings."""

    def __init__(self, high_severity: Sequence[str] = None) -> None:
        self._high = frozenset(high_severity) if high_severity else HIGH_SEVERITY_FINDINGS
        self._cells: List[QuarantineCell] = []

    def quarantine(self, record: AttackerRecord) -> QuarantineCell:
        findings = list(record.findings)
        severe = any(finding in self._high for finding in findings)
        profile = IsolationProfile.STRICT if severe else IsolationProfile.COMPAT
        cell = QuarantineCell(
            cell_id=f"cell-{uuid.uuid4().hex[:10]}",
            attacker_id=record.attacker_id,
            profile=profile,
            locked=True,
            findings_snapshot=findings,
        )
        record.quarantined = True
        self._cells.append(cell)
        return cell

    def cells(self) -> List[QuarantineCell]:
        return list(self._cells)
