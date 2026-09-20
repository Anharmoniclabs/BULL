"""Adversary registry: tabulates attackers and clusters them into swarms."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .contracts import AttackerRecord


def _normalize(task: str) -> set:
    return set(re.findall(r"[a-z0-9]+", task.lower()))


def task_similarity(a: str, b: str) -> float:
    """Jaccard similarity of normalized task tokens."""
    left, right = _normalize(a), _normalize(b)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


class AdversaryRegistry:
    """Central tabulation of every attacker BULL has observed."""

    def __init__(self, swarm_threshold: float = 0.6) -> None:
        self._records: Dict[str, AttackerRecord] = {}
        self._swarm_counter = 0
        self._swarm_threshold = swarm_threshold

    def upsert(
        self,
        label: str,
        fingerprint=None,
        initial_task: str = "",
        findings: Optional[List[str]] = None,
    ) -> AttackerRecord:
        record = self._find_by_label(label)
        if record is None:
            record = AttackerRecord(label=label)
            self._records[record.attacker_id] = record
        record.observation_count += 1
        if fingerprint is not None:
            record.fingerprint = fingerprint
        if initial_task:
            record.initial_task = initial_task
            self._assign_swarm(record)
        if findings:
            record.findings = sorted(set(record.findings) | set(findings))
        return record

    def _find_by_label(self, label: str) -> Optional[AttackerRecord]:
        for record in self._records.values():
            if record.label == label:
                return record
        return None

    def _assign_swarm(self, record: AttackerRecord) -> None:
        for other in self._records.values():
            if other.attacker_id == record.attacker_id:
                continue
            if not other.initial_task:
                continue
            if task_similarity(record.initial_task, other.initial_task) >= self._swarm_threshold:
                if other.swarm_id:
                    record.swarm_id = other.swarm_id
                    return
        self._swarm_counter += 1
        record.swarm_id = f"swarm-{self._swarm_counter:03d}"

    def get(self, attacker_id: str) -> Optional[AttackerRecord]:
        return self._records.get(attacker_id)

    def all(self) -> List[AttackerRecord]:
        return list(self._records.values())

    def tabulate(self) -> Dict[str, object]:
        records = self.all()
        families: Dict[str, int] = {}
        swarms: Dict[str, int] = {}
        for record in records:
            family = record.fingerprint.family if record.fingerprint else "unknown"
            families[family] = families.get(family, 0) + 1
            if record.swarm_id:
                swarms[record.swarm_id] = swarms.get(record.swarm_id, 0) + 1
        return {
            "total_attackers": len(records),
            "by_model_family": families,
            "swarms": swarms,
            "quarantined": sum(1 for r in records if r.quarantined),
        }
