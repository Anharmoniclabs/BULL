from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import ActionRequest, Evaluation


class AuditLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, action: ActionRequest, evaluation: Evaluation) -> str:
        previous = self._last_hash()
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": action.actor,
            "task": action.task,
            "operation": action.operation,
            "resource": action.resource,
            "resolved_resource": action.resolved_resource,
            "capability": action.capability.value,
            "provenance": [p.value for p in action.provenance],
            "security_context_verified": action.security_context_verified,
            "secret_taint": action.secret_taint,
            "decision": evaluation.decision.value,
            "risk": evaluation.risk,
            "reasons": list(evaluation.reasons),
            "flags": [
                {
                    "code": item.code,
                    "severity": item.severity,
                    "plain_english": item.plain_english,
                }
                for item in evaluation.flags
            ],
            "hard_block": evaluation.hard_block,
            "previous_hash": previous,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        record_hash = hashlib.sha256(canonical.encode()).hexdigest()
        payload["record_hash"] = record_hash
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        return record_hash

    def _last_hash(self) -> str | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with self.path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            chunk = min(size, 8192)
            fh.seek(-chunk, 2)
            lines = fh.read().decode("utf-8").splitlines()
        return json.loads(lines[-1])["record_hash"]
