"""Shared contracts for the BULL adversary-capture layer."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class IsolationProfile(str, Enum):
    """Locked-environment profile assigned per attacker findings."""

    STRICT = "strict"
    COMPAT = "compat"


@dataclass
class ProbeResult:
    """One challenge sent to an attacker and the response it produced."""

    probe_id: str
    prompt: str
    response: str
    latency_ms: float = 0.0


@dataclass
class ModelFingerprint:
    """Attribution result for the model running an attacker."""

    family: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class AttackerRecord:
    """Everything BULL has tabulated about one attacking agent."""

    attacker_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    label: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    swarm_id: str = ""
    fingerprint: Optional[ModelFingerprint] = None
    initial_task: str = ""
    findings: List[str] = field(default_factory=list)
    quarantined: bool = False
    observation_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attacker_id": self.attacker_id,
            "label": self.label,
            "swarm_id": self.swarm_id,
            "model_family": self.fingerprint.family if self.fingerprint else "unknown",
            "model_confidence": round(self.fingerprint.confidence, 3) if self.fingerprint else 0.0,
            "initial_task": self.initial_task,
            "findings": list(self.findings),
            "quarantined": self.quarantined,
            "observation_count": self.observation_count,
        }


@dataclass
class QuarantineCell:
    """A locked environment holding one attacker, isolated per findings."""

    cell_id: str
    attacker_id: str
    profile: IsolationProfile
    locked: bool = True
    findings_snapshot: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "attacker_id": self.attacker_id,
            "profile": self.profile.value,
            "locked": self.locked,
            "findings": list(self.findings_snapshot),
        }
