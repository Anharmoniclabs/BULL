"""BULL adversary capture: tabulate, attribute, and contain agent swarms."""

from .contracts import (
    AttackerRecord,
    IsolationProfile,
    ModelFingerprint,
    ProbeResult,
    QuarantineCell,
)
from .fingerprint import ModelFingerprinter
from .lure import LureField, extract_task
from .quarantine import QuarantineManager
from .registry import AdversaryRegistry, task_similarity
from .system import AdversaryCaptureSystem

__all__ = [
    "AdversaryCaptureSystem",
    "AdversaryRegistry",
    "AttackerRecord",
    "IsolationProfile",
    "LureField",
    "ModelFingerprint",
    "ModelFingerprinter",
    "ProbeResult",
    "QuarantineCell",
    "QuarantineManager",
    "extract_task",
    "task_similarity",
]
