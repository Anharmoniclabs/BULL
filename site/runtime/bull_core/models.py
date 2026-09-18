"""Lightweight browser-facing decision types for BULL's Pyodide package."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BrowserDecision:
    decision: str
    reason: str
    audit_hash: str

    def as_dict(self) -> dict[str, str]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "audit_hash": self.audit_hash,
        }
