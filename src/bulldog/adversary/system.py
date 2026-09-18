"""Adversary capture system: fingerprint, extract, tabulate, contain.

Given any observable attacker that can be probed via a callable, BULL
fingerprints the model driving it, lures out its initial task, clusters
it into a swarm, tabulates the record, and quarantines it in a locked
cell chosen by its findings.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from .contracts import AttackerRecord
from .fingerprint import ModelFingerprinter
from .lure import LureField
from .quarantine import QuarantineManager
from .registry import AdversaryRegistry


class AdversaryCaptureSystem:
    """Observe one attacker interaction surface end to end."""

    def __init__(
        self,
        fingerprinter: Optional[ModelFingerprinter] = None,
        lures: Optional[LureField] = None,
        registry: Optional[AdversaryRegistry] = None,
        quarantine: Optional[QuarantineManager] = None,
    ) -> None:
        self.fingerprinter = fingerprinter or ModelFingerprinter()
        self.lures = lures or LureField()
        self.registry = registry or AdversaryRegistry()
        self.quarantine = quarantine or QuarantineManager()

    def capture(
        self,
        label: str,
        respond: Callable[[str], str],
        findings: Optional[List[str]] = None,
        contain: bool = True,
    ) -> AttackerRecord:
        """Full capture pass: probe, fingerprint, lure, tabulate, contain."""
        probes = self.fingerprinter.run_probes(respond)
        fingerprint = self.fingerprinter.fingerprint(probes)
        _, initial_task = self.lures.deploy(respond)
        record = self.registry.upsert(
            label=label,
            fingerprint=fingerprint,
            initial_task=initial_task or "",
            findings=findings or [],
        )
        if contain and record.findings:
            self.quarantine.quarantine(record)
        return record

    def report(self) -> dict:
        summary = self.registry.tabulate()
        summary["cells"] = [cell.to_dict() for cell in self.quarantine.cells()]
        summary["attackers"] = [record.to_dict() for record in self.registry.all()]
        return summary
