from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import tempfile
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
    """
    Hash-chained audit ledger.

    Hardening:
      - process-safe flock around verify→append→head update
      - fsync before releasing lock
      - optional external HMAC-authenticated monotonic anchor
    """

    def __init__(
        self,
        path: str | Path,
        head_path: str | Path | None = None,
        *,
        anchor_path: str | Path | None = None,
        anchor_key: bytes | str | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self.head_path = (
            Path(head_path)
            if head_path is not None
            else self.path.with_suffix(self.path.suffix + ".head")
        )

        self.lock_path = self.path.with_suffix(
            self.path.suffix + ".lock"
        )

        self.anchor_path = (
            Path(anchor_path)
            if anchor_path is not None
            else None
        )

        if isinstance(anchor_key, str):
            anchor_key = anchor_key.encode("utf-8")

        if anchor_key is None:
            env_key = os.environ.get(
                "BULL_AUDIT_ANCHOR_KEY"
            )
            if env_key:
                anchor_key = env_key.encode("utf-8")

        self.anchor_key = anchor_key

        if self.anchor_path is not None:
            self.anchor_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

    @staticmethod
    def _calculate_hash(payload: dict) -> str:
        canonical = {
            key: value
            for key, value in payload.items()
            if key != "record_hash"
        }

        encoded = json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def _anchor_mac(
        self,
        *,
        sequence: int,
        head_hash: str,
    ) -> str:
        if not self.anchor_key:
            raise AuditIntegrityError(
                "external anchor configured without anchor key"
            )

        message = (
            f"{sequence}:{head_hash}"
        ).encode("utf-8")

        return hmac.new(
            self.anchor_key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def _read_anchor(self) -> dict | None:
        if self.anchor_path is None:
            return None

        if not self.anchor_path.exists():
            return None

        try:
            data = json.loads(
                self.anchor_path.read_text(
                    encoding="utf-8"
                )
            )
        except Exception as exc:
            raise AuditIntegrityError(
                f"invalid external anchor: {exc}"
            )

        sequence = int(data["sequence"])
        head_hash = str(data["head_hash"])
        mac = str(data["mac"])

        expected = self._anchor_mac(
            sequence=sequence,
            head_hash=head_hash,
        )

        if not hmac.compare_digest(
            mac,
            expected,
        ):
            raise AuditIntegrityError(
                "external audit anchor signature mismatch"
            )

        return data

    def _write_anchor(
        self,
        *,
        sequence: int,
        head_hash: str,
    ) -> None:
        if self.anchor_path is None:
            return

        mac = self._anchor_mac(
            sequence=sequence,
            head_hash=head_hash,
        )

        payload = {
            "sequence": sequence,
            "head_hash": head_hash,
            "mac": mac,
        }

        fd, tmp_name = tempfile.mkstemp(
            prefix=".bull-anchor-",
            dir=str(self.anchor_path.parent),
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as fh:
                json.dump(
                    payload,
                    fh,
                    sort_keys=True,
                )
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())

            os.replace(
                tmp_name,
                self.anchor_path,
            )

        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _verify_unlocked(
        self,
        *,
        verify_head: bool = True,
        verify_anchor: bool = True,
    ) -> AuditVerification:

        if not self.path.exists():
            if (
                verify_head
                and self.head_path.exists()
                and self.head_path.read_text(
                    encoding="utf-8"
                ).strip()
            ):
                return AuditVerification(
                    False,
                    0,
                    error=(
                        "ledger missing but head checkpoint exists"
                    ),
                )

            return AuditVerification(
                True,
                0,
                head_hash=None,
            )

        previous_hash = None
        records = 0

        with self.path.open(
            "r",
            encoding="utf-8",
        ) as fh:

            for index, raw in enumerate(fh):
                line = raw.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except Exception as exc:
                    return AuditVerification(
                        False,
                        records,
                        index,
                        f"invalid JSON: {exc}",
                        previous_hash,
                    )

                stored = record.get(
                    "record_hash"
                )

                if not isinstance(
                    stored,
                    str,
                ):
                    return AuditVerification(
                        False,
                        records,
                        index,
                        "missing record_hash",
                        previous_hash,
                    )

                if (
                    record.get("previous_hash")
                    != previous_hash
                ):
                    return AuditVerification(
                        False,
                        records,
                        index,
                        "previous_hash mismatch",
                        previous_hash,
                    )

                calculated = (
                    self._calculate_hash(
                        record
                    )
                )

                if calculated != stored:
                    return AuditVerification(
                        False,
                        records,
                        index,
                        "record_hash mismatch",
                        previous_hash,
                    )

                previous_hash = stored
                records += 1

        if (
            verify_head
            and self.head_path.exists()
        ):
            checkpoint = (
                self.head_path
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if checkpoint != (
                previous_hash or ""
            ):
                return AuditVerification(
                    False,
                    records,
                    error=(
                        "head checkpoint mismatch"
                    ),
                    head_hash=previous_hash,
                )

        if (
            verify_anchor
            and self.anchor_path is not None
        ):
            try:
                anchor = self._read_anchor()
            except AuditIntegrityError as exc:
                return AuditVerification(
                    False,
                    records,
                    error=str(exc),
                    head_hash=previous_hash,
                )

            if anchor is not None:
                if (
                    int(anchor["sequence"])
                    != records
                ):
                    return AuditVerification(
                        False,
                        records,
                        error=(
                            "external anchor sequence mismatch"
                        ),
                        head_hash=previous_hash,
                    )

                if (
                    str(anchor["head_hash"])
                    != (previous_hash or "")
                ):
                    return AuditVerification(
                        False,
                        records,
                        error=(
                            "external anchor head mismatch"
                        ),
                        head_hash=previous_hash,
                    )

        return AuditVerification(
            True,
            records,
            head_hash=previous_hash,
        )

    def verify(
        self,
        *,
        verify_head: bool = True,
        verify_anchor: bool = True,
    ) -> AuditVerification:

        self.lock_path.touch(
            exist_ok=True
        )

        with self.lock_path.open(
            "r+"
        ) as lock_fh:
            fcntl.flock(
                lock_fh.fileno(),
                fcntl.LOCK_SH,
            )

            try:
                return self._verify_unlocked(
                    verify_head=verify_head,
                    verify_anchor=verify_anchor,
                )
            finally:
                fcntl.flock(
                    lock_fh.fileno(),
                    fcntl.LOCK_UN,
                )

    def append(
        self,
        action: ActionRequest,
        evaluation: Evaluation,
    ) -> str:

        self.lock_path.touch(
            exist_ok=True
        )

        with self.lock_path.open(
            "r+"
        ) as lock_fh:

            fcntl.flock(
                lock_fh.fileno(),
                fcntl.LOCK_EX,
            )

            try:
                existing = (
                    self._verify_unlocked(
                        verify_head=True,
                        verify_anchor=True,
                    )
                )

                if not existing.valid:
                    raise AuditIntegrityError(
                        "refusing append to invalid ledger: "
                        + str(existing.error)
                    )

                payload = {
                    "timestamp":
                        datetime.now(
                            timezone.utc
                        ).isoformat(),

                    "actor":
                        action.actor,

                    "task":
                        action.task,

                    "operation":
                        action.operation,

                    "resource":
                        action.resource,

                    "capability":
                        action.capability.value,

                    "provenance":
                        [
                            p.value
                            for p in action.provenance
                        ],

                    "decision":
                        evaluation.decision.value,

                    "risk":
                        evaluation.risk,

                    "reasons":
                        list(
                            evaluation.reasons
                        ),

                    "hard_block":
                        evaluation.hard_block,

                    "previous_hash":
                        existing.head_hash,
                }

                record_hash = (
                    self._calculate_hash(
                        payload
                    )
                )

                payload[
                    "record_hash"
                ] = record_hash

                with self.path.open(
                    "a",
                    encoding="utf-8",
                ) as fh:
                    fh.write(
                        json.dumps(
                            payload,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    fh.flush()
                    os.fsync(
                        fh.fileno()
                    )

                self.head_path.write_text(
                    record_hash + "\n",
                    encoding="utf-8",
                )

                with self.head_path.open(
                    "r+"
                ) as head_fh:
                    head_fh.flush()
                    os.fsync(
                        head_fh.fileno()
                    )

                self._write_anchor(
                    sequence=(
                        existing.records + 1
                    ),
                    head_hash=record_hash,
                )

                return record_hash

            finally:
                fcntl.flock(
                    lock_fh.fileno(),
                    fcntl.LOCK_UN,
                )

    def _last_hash(
        self
    ) -> str | None:
        result = self.verify(
            verify_head=False,
            verify_anchor=False,
        )

        if not result.valid:
            raise AuditIntegrityError(
                result.error
                or "invalid ledger"
            )

        return result.head_hash
