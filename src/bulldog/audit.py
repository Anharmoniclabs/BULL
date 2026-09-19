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
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .models import ActionRequest, Evaluation
from .audit_transport import HTTPSAnchorTransport, RelayAnchorTransport


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
    """Hash-chained audit ledger with optional local and remote anchoring.

    If a remote anchor is configured, each append sends only the monotonic
    sequence/head hash plus an HMAC. A local remote-checkpoint is advanced only
    after the remote endpoint acknowledges the anchor. If delivery fails, the
    ledger is intentionally left in a state that refuses the next append until
    the missing remote anchor is reconciled.
    """

    def __init__(
        self,
        path: str | Path,
        head_path: str | Path | None = None,
        *,
        anchor_path: str | Path | None = None,
        anchor_key: bytes | str | None = None,
        remote_anchor_url: str | None = None,
        remote_anchor_key: bytes | str | None = None,
        remote_timeout: float = 5.0,
        transport: HTTPSAnchorTransport | RelayAnchorTransport | None = None,
        max_ledger_bytes: int = 256 * 1024 * 1024,
    ):
        self.path = Path(path)
        self.transport = transport
        if type(max_ledger_bytes) is not int or max_ledger_bytes < 1:
            raise ValueError("audit storage budget must be a positive integer")
        self.max_ledger_bytes = max_ledger_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self.head_path = (
            Path(head_path)
            if head_path is not None
            else self.path.with_suffix(self.path.suffix + ".head")
        )
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.anchor_path = Path(anchor_path) if anchor_path is not None else None
        self.remote_checkpoint_path = self.path.with_suffix(
            self.path.suffix + ".remote"
        )

        if isinstance(anchor_key, str):
            anchor_key = anchor_key.encode("utf-8")
        if anchor_key is None:
            env_key = os.environ.get("BULL_AUDIT_ANCHOR_KEY")
            if env_key:
                anchor_key = env_key.encode("utf-8")
        self.anchor_key = anchor_key

        self.remote_anchor_url = (
            str(remote_anchor_url).strip()
            if remote_anchor_url is not None
            else os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL", "").strip()
        ) or None

        if isinstance(remote_anchor_key, str):
            remote_anchor_key = remote_anchor_key.encode("utf-8")
        if remote_anchor_key is None:
            env_remote_key = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY")
            if env_remote_key:
                remote_anchor_key = env_remote_key.encode("utf-8")
        self.remote_anchor_key = remote_anchor_key
        self.remote_timeout = float(remote_timeout)
        if transport is not None:
            # Transport configuration is independent of the legacy URL API.
            self.remote_anchor_url = None
            self.remote_anchor_key = None

        if self.anchor_path is not None:
            self.anchor_path.parent.mkdir(parents=True, exist_ok=True)

        if self.remote_anchor_url is not None:
            parsed = urlsplit(self.remote_anchor_url)
            if parsed.scheme != "https" or not parsed.hostname:
                raise AuditIntegrityError(
                    "remote audit anchor must be an absolute HTTPS URL"
                )
            if parsed.username or parsed.password:
                raise AuditIntegrityError(
                    "remote audit anchor URL credentials are forbidden"
                )
            if not self.remote_anchor_key:
                raise AuditIntegrityError(
                    "remote audit anchor configured without authentication key"
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

    @staticmethod
    def _mac(
        key: bytes | None,
        *,
        sequence: int,
        head_hash: str,
    ) -> str:
        if not key:
            raise AuditIntegrityError("audit anchor key is missing")
        message = f"{sequence}:{head_hash}".encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _anchor_mac(self, *, sequence: int, head_hash: str) -> str:
        return self._mac(
            self.anchor_key,
            sequence=sequence,
            head_hash=head_hash,
        )

    def _remote_mac(self, *, sequence: int, head_hash: str) -> str:
        return self._mac(
            self.remote_anchor_key,
            sequence=sequence,
            head_hash=head_hash,
        )

    def _read_anchor(self) -> dict | None:
        if self.anchor_path is None or not self.anchor_path.exists():
            return None
        try:
            data = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            sequence = int(data["sequence"])
            head_hash = str(data["head_hash"])
            mac = str(data["mac"])
        except Exception as exc:
            raise AuditIntegrityError(f"invalid external anchor: {exc}")

        expected = self._anchor_mac(sequence=sequence, head_hash=head_hash)
        if not hmac.compare_digest(mac, expected):
            raise AuditIntegrityError("external audit anchor signature mismatch")
        return data

    def _write_atomic_json(self, path: Path, payload: dict, prefix: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=prefix, dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _write_anchor(self, *, sequence: int, head_hash: str) -> None:
        if self.anchor_path is None:
            return
        self._write_atomic_json(
            self.anchor_path,
            {
                "sequence": sequence,
                "head_hash": head_hash,
                "mac": self._anchor_mac(
                    sequence=sequence,
                    head_hash=head_hash,
                ),
            },
            ".bull-anchor-",
        )

    @property
    def production_anchor_ready(self) -> bool:
        return isinstance(self.transport, (HTTPSAnchorTransport, RelayAnchorTransport)) and self.transport.production_ready

    def _write_remote_anchor(self, *, sequence: int, head_hash: str, record: dict | None = None) -> None:
        if self.transport is not None:
            try:
                if record is None:
                    raise AuditIntegrityError("transport requires the complete audit record")
                ack = self.transport.submit(sequence, record)
                self.transport.identity.check_ack(ack, sequence, head_hash)
                self._write_atomic_json(self.remote_checkpoint_path, ack, ".bull-remote-anchor-")
            except Exception as exc:
                raise AuditIntegrityError("remote audit anchor delivery failed: " + str(exc)) from exc
            return
        if self.remote_anchor_url is None:
            return

        payload = {
            "format": "bull-remote-anchor-v1",
            "sequence": int(sequence),
            "head_hash": str(head_hash),
            "mac": self._remote_mac(
                sequence=sequence,
                head_hash=head_hash,
            ),
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.remote_anchor_url,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "BULL-AuditAnchor/1",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.remote_timeout) as response:
                status = int(getattr(response, "status", response.getcode()))
                response.read(4096)
        except Exception as exc:
            raise AuditIntegrityError(
                "remote audit anchor delivery failed: " + str(exc)
            ) from exc

        if status < 200 or status >= 300:
            raise AuditIntegrityError(
                f"remote audit anchor rejected update with HTTP {status}"
            )

        # Advance only after a successful acknowledgement. This checkpoint makes
        # a failed delivery detectable on the next verify/append.
        self._write_atomic_json(
            self.remote_checkpoint_path,
            payload,
            ".bull-remote-anchor-",
        )

    def _verify_remote_checkpoint(
        self,
        *,
        records: int,
        head_hash: str | None,
    ) -> str | None:
        if self.transport is not None:
            if records == 0 and not self.remote_checkpoint_path.exists():
                return None
            try:
                data = json.loads(self.remote_checkpoint_path.read_text())
                self.transport.identity.check_ack(data, records, head_hash or "")
            except Exception as exc:
                return "remote audit checkpoint invalid: " + str(exc)
            return None
        if self.remote_anchor_url is None:
            return None
        if records == 0 and not self.remote_checkpoint_path.exists():
            return None
        if not self.remote_checkpoint_path.exists():
            return "remote audit checkpoint missing"

        try:
            data = json.loads(
                self.remote_checkpoint_path.read_text(encoding="utf-8")
            )
            sequence = int(data["sequence"])
            remote_head = str(data["head_hash"])
            supplied = str(data["mac"])
            expected = self._remote_mac(
                sequence=sequence,
                head_hash=remote_head,
            )
        except Exception as exc:
            return "invalid remote audit checkpoint: " + str(exc)

        if not hmac.compare_digest(supplied, expected):
            return "remote audit checkpoint signature mismatch"
        if sequence != records:
            return "remote audit checkpoint sequence mismatch"
        if remote_head != (head_hash or ""):
            return "remote audit checkpoint head mismatch"
        return None

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
                and self.head_path.read_text(encoding="utf-8").strip()
            ):
                return AuditVerification(
                    False, 0, error="ledger missing but head checkpoint exists"
                )
            remote_error = self._verify_remote_checkpoint(records=0, head_hash=None)
            if remote_error:
                return AuditVerification(False, 0, error=remote_error)
            return AuditVerification(True, 0, head_hash=None)

        previous_hash = None
        records = 0
        if self.path.stat().st_size > self.max_ledger_bytes:
            return AuditVerification(False, 0, error="audit storage budget exceeded")
        with self.path.open("r", encoding="utf-8") as fh:
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

                stored = record.get("record_hash")
                if not isinstance(stored, str):
                    return AuditVerification(
                        False, records, index, "missing record_hash", previous_hash
                    )
                if record.get("previous_hash") != previous_hash:
                    return AuditVerification(
                        False,
                        records,
                        index,
                        "previous_hash mismatch",
                        previous_hash,
                    )
                if self._calculate_hash(record) != stored:
                    return AuditVerification(
                        False,
                        records,
                        index,
                        "record_hash mismatch",
                        previous_hash,
                    )
                previous_hash = stored
                records += 1

        if verify_head and self.head_path.exists():
            checkpoint = self.head_path.read_text(encoding="utf-8").strip()
            if checkpoint != (previous_hash or ""):
                return AuditVerification(
                    False,
                    records,
                    error="head checkpoint mismatch",
                    head_hash=previous_hash,
                )

        if verify_anchor and self.anchor_path is not None:
            try:
                anchor = self._read_anchor()
            except AuditIntegrityError as exc:
                return AuditVerification(
                    False, records, error=str(exc), head_hash=previous_hash
                )
            if anchor is not None:
                if int(anchor["sequence"]) != records:
                    return AuditVerification(
                        False,
                        records,
                        error="external anchor sequence mismatch",
                        head_hash=previous_hash,
                    )
                if str(anchor["head_hash"]) != (previous_hash or ""):
                    return AuditVerification(
                        False,
                        records,
                        error="external anchor head mismatch",
                        head_hash=previous_hash,
                    )

        if verify_anchor:
            remote_error = self._verify_remote_checkpoint(
                records=records,
                head_hash=previous_hash,
            )
            if remote_error:
                return AuditVerification(
                    False,
                    records,
                    error=remote_error,
                    head_hash=previous_hash,
                )

        return AuditVerification(True, records, head_hash=previous_hash)

    def verify(
        self,
        *,
        verify_head: bool = True,
        verify_anchor: bool = True,
    ) -> AuditVerification:
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("r+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_SH)
            try:
                return self._verify_unlocked(
                    verify_head=verify_head,
                    verify_anchor=verify_anchor,
                )
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def _append_payload(self, payload: dict) -> str:
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("r+") as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                existing = self._verify_unlocked(
                    verify_head=True,
                    verify_anchor=True,
                )
                if not existing.valid:
                    raise AuditIntegrityError(
                        "refusing append to invalid ledger: " + str(existing.error)
                    )

                record = dict(payload)
                record["previous_hash"] = existing.head_hash
                record_hash = self._calculate_hash(record)
                record["record_hash"] = record_hash
                encoded_record = json.dumps(record, sort_keys=True) + "\n"
                if self.transport is not None and len(encoded_record.encode()) > 60 * 1024:
                    raise AuditIntegrityError("audit record exceeds transport framing budget")
                existing_bytes = self.path.stat().st_size if self.path.exists() else 0
                if existing_bytes + len(encoded_record.encode()) > self.max_ledger_bytes:
                    raise AuditIntegrityError("audit storage budget exhausted")

                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(encoded_record)
                    fh.flush()
                    os.fsync(fh.fileno())

                self.head_path.write_text(record_hash + "\n", encoding="utf-8")
                with self.head_path.open("r+") as head_fh:
                    head_fh.flush()
                    os.fsync(head_fh.fileno())

                sequence = existing.records + 1
                self._write_anchor(sequence=sequence, head_hash=record_hash)
                self._write_remote_anchor(sequence=sequence, head_hash=record_hash, record=record)
                return record_hash
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def reconcile_remote(self) -> None:
        """Explicitly retry the latest audit checkpoint; never replay execution."""
        if self.transport is None:
            raise AuditIntegrityError("recovery requires a versioned audit transport")
        self.lock_path.touch(exist_ok=True)
        with self.lock_path.open("r+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                result = self._verify_unlocked(verify_anchor=False)
                if not result.valid or result.records == 0:
                    raise AuditIntegrityError("cannot recover an empty or invalid local ledger")
                last = None
                with self.path.open() as stream:
                    for line in stream:
                        if line.strip():
                            last = json.loads(line)
                assert last is not None
                self._write_remote_anchor(sequence=result.records, head_hash=result.head_hash or "", record=last)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def append(
        self,
        action: ActionRequest,
        evaluation: Evaluation,
    ) -> str:
        return self._append_payload(
            {
                "record_type": "action_evaluation",
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
                "metadata": {
                    str(key): str(value)
                    for key, value in sorted(action.metadata.items())
                },
            }
        )

    def append_event(self, event_type: str, data: dict) -> str:
        if not event_type:
            raise ValueError("event_type cannot be empty")
        return self._append_payload(
            {
                "record_type": "runtime_event",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": str(event_type),
                "data": data,
            }
        )

    def _last_hash(self) -> str | None:
        result = self.verify(verify_head=False, verify_anchor=False)
        if not result.valid:
            raise AuditIntegrityError(result.error or "invalid ledger")
        return result.head_hash
