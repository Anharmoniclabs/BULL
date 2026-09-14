from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .models import ActionRequest, Decision


@dataclass(frozen=True)
class Advisory:
    risk: float
    recommendation: Decision
    reason: str


class AdvisoryModel(Protocol):
    def evaluate(self, action: ActionRequest) -> Advisory: ...


class NullAdvisoryModel:
    """Safe default: ML is optional and never grants authority."""

    def evaluate(self, action: ActionRequest) -> Advisory:
        return Advisory(0.0, Decision.ALLOW, "no advisory model configured")
