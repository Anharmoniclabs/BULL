"""Authenticated audit on one trusted host, without an external collector.

The authority owns the key and checkpoint; the separate agent account cannot
read them. This does not protect against a host administrator rolling back or
rewriting both the log and its checkpoint.
"""

import os
from pathlib import Path
import stat

from .audit import AuditIntegrityError, AuditLedger, AuditVerification


def private_key(path: str | Path) -> bytes:
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("local audit key must not follow symlinks")
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError("local audit key directory must be private to the authority")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or not 32 <= info.st_size <= 4096
        ):
            raise ValueError("local audit key must be a private, bounded file")
        return os.read(fd, 4097)
    finally:
        os.close(fd)


class LocalAuditLedger(AuditLedger):
    """Require the installation's authenticated checkpoint on every append."""

    def __init__(self, path, *, anchor_path, anchor_key):
        if not isinstance(anchor_key, bytes) or len(anchor_key) < 32:
            raise ValueError("local audit needs an installation-specific key")
        super().__init__(
            path,
            anchor_path=anchor_path,
            anchor_key=anchor_key,
            remote_anchor_url="",
            remote_anchor_key=b"",
        )
        if self.anchor_path == self.path or self.anchor_path == self.head_path:
            raise ValueError("local audit checkpoint must be separate from its ledger")

    @property
    def local_anchor_ready(self):
        return self.verify().valid

    def _verify_unlocked(self, *, verify_head=True, verify_anchor=True):
        # Even an empty installation has an authenticated zero-record checkpoint.
        # Missing checkpoints are never silently recreated after a crash/deletion.
        result = super()._verify_unlocked(
            verify_head=verify_head, verify_anchor=verify_anchor
        )
        if not result.valid:
            return result
        try:
            anchor = self._read_anchor()
            if anchor is None:
                raise AuditIntegrityError("local audit checkpoint missing")
            if anchor["sequence"] != result.records or anchor["head_hash"] != (
                result.head_hash or ""
            ):
                raise AuditIntegrityError(
                    "local audit checkpoint does not match ledger"
                )
        except (AuditIntegrityError, OSError, KeyError) as exc:
            return AuditVerification(
                False, result.records, error=str(exc), head_hash=result.head_hash
            )
        return result


def local_ledger_from_environment():
    if os.environ.get("BULL_AUDIT_MODE") != "local":
        raise ValueError("select the local audit profile explicitly")
    path = Path(os.environ["BULL_AUDIT_LEDGER"]).absolute()
    checkpoint = Path(os.environ["BULL_LOCAL_AUDIT_CHECKPOINT"]).absolute()
    for item in (path, checkpoint):
        if item.resolve() != item:
            raise ValueError("local audit paths must not follow symlinks")
        parent = item.parent.stat()
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ValueError("local audit directory must be private to the authority")
    ledger = LocalAuditLedger(
        path,
        anchor_path=checkpoint,
        anchor_key=private_key(os.environ["BULL_LOCAL_AUDIT_KEY_FILE"]),
    )
    if not ledger.local_anchor_ready:
        raise AuditIntegrityError("local authenticated audit checkpoint did not verify")
    return ledger
