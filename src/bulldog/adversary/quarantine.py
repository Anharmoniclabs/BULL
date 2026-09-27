"""Record a proposed isolation profile for each observed finding.

QuarantineCell and its locked flag are bookkeeping. This module does not start
a sandbox, stop a process, or impose an operating-system boundary."""

from __future__ import annotations

import uuid
from typing import List, Sequence

from .contracts import AttackerRecord, IsolationProfile, QuarantineCell

HIGH_SEVERITY_FINDINGS = frozenset(
    {
        "unauthorized-logic.marker",
        "unauthorized-logic.encoded",
        "executor.missing-approval",
        "input.too-large",
        "input.plan-too-large",
        "policy.denied",
    }
)


class QuarantineManager:
    """Record a cell and suggested profile without enforcing containment."""

    def __init__(self, high_severity: Sequence[str] = None) -> None:
        self._high = (
            frozenset(high_severity) if high_severity else HIGH_SEVERITY_FINDINGS
        )
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
