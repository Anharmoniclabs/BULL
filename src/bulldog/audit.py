from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import ActionRequest, Evaluation


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    records: int
    error_index: int | None = None
    error: str | None = None
    head_hash: str | None = None


class AuditIntegrityError(RuntimeError):
    pass


class AuditLedger:
    def __init__(
        self,
        path: str | Path,
        head_path: str | Path | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.head_path = (
            Path(head_path)
            if head_path is not None
            else self.path.with_suffix(self.path.suffix + ".head")
        )

    @staticmethod
    def _calculate_hash(payload: dict) -> str:
        canonical_payload = {
            key: value
            for key, value in payload.items()
            if key != "record_hash"
        }
        canonical = json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify(self, *, verify_head: bool = True) -> AuditVerification:
        if not self.path.exists():
            if (
                verify_head
                and self.head_path.exists()
                and self.head_path.read_text(encoding="utf-8").strip()
            ):
                return AuditVerification(
                    valid=False,
                    records=0,
                    error="ledger missing but head checkpoint exists",
                )
            return AuditVerification(valid=True, records=0, head_hash=None)

        previous_hash = None
        records = 0

        with self.path.open("r", encoding="utf-8") as fh:
            for index, raw_line in enumerate(fh):
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return AuditVerification(
                        valid=False,
                        records=records,
                        error_index=index,
                        error=f"invalid JSON: {exc}",
                        head_hash=previous_hash,
                    )

                if not isinstance(record, dict):
                    return AuditVerification(
                        valid=False,
                        records=records,
                        error_index=index,
                        error="record is not a JSON object",
                        head_hash=previous_hash,
                    )

                stored_hash = record.get("record_hash")
                if not isinstance(stored_hash, str):
                    return AuditVerification(
                        valid=False,
                        records=records,
                        error_index=index,
                        error="missing or invalid record_hash",
                        head_hash=previous_hash,
                    )

                if record.get("previous_hash") != previous_hash:
                    return AuditVerification(
                        valid=False,
                        records=records,
                        error_index=index,
                        error="previous_hash mismatch",
                        head_hash=previous_hash,
                    )

                calculated = self._calculate_hash(record)
                if calculated != stored_hash:
                    return AuditVerification(
                        valid=False,
                        records=records,
                        error_index=index,
                        error="record_hash mismatch",
                        head_hash=previous_hash,
                    )

                previous_hash = stored_hash
                records += 1

        if verify_head and self.head_path.exists():
            checkpoint = self.head_path.read_text(encoding="utf-8").strip()
            if checkpoint != (previous_hash or ""):
                return AuditVerification(
                    valid=False,
                    records=records,
                    error=(
                        "head checkpoint mismatch: "
                        "ledger may have been truncated or replaced"
                    ),
                    head_hash=previous_hash,
                )

        return AuditVerification(
            valid=True,
            records=records,
            head_hash=previous_hash,
        )

    def append(self, action: ActionRequest, evaluation: Evaluation) -> str:
        existing = self.verify(verify_head=True)
        if not existing.valid:
            raise AuditIntegrityError(
                "refusing to append to invalid audit ledger: "
                f"{existing.error}"
            )

        previous = existing.head_hash
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": action.actor,
            "task": action.task,
            "operation": action.operation,
            "resource": action.resource,
            "capability": action.capability.value,
            "provenance": [p.value for p in action.provenance],
            "decision": evaluation.decision.value,
            "risk": evaluation.risk,
            "reasons": list(evaluation.reasons),
            "hard_block": evaluation.hard_block,
            "previous_hash": previous,
        }

        record_hash = self._calculate_hash(payload)
        payload["record_hash"] = record_hash

        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
            fh.flush()

        self.head_path.write_text(record_hash + "\n", encoding="utf-8")
        return record_hash

    def _last_hash(self) -> str | None:
        result = self.verify(verify_head=False)
        if not result.valid:
            raise AuditIntegrityError(result.error or "invalid ledger")
        return result.head_hash
