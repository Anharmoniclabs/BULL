"""Host-side audit evidence helpers for deployment tests, not guest authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from bulldog.anchor_service import AnchorError


def anchor_master(key_file: Path | None = None) -> bytes:
    """Read exact deployment key bytes without including them in errors/reports."""
    if key_file is None:
        key = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY", "").encode()
    else:
        fd = os.open(key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
                    or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 4096):
                raise AnchorError("anchor key file must be private, owner-controlled, and bounded")
            key = stream.read(4097)
    if not 32 <= len(key) <= 4096:
        raise AnchorError("provide the collector's exact master key, between 32 and 4096 bytes")
    return key


class ReceiptTransport:
    """Retain only authenticated upstream acknowledgements for exact correlation."""

    def __init__(self, upstream, receipt_path: Path):
        self.upstream = upstream
        self.identity = upstream.identity
        self.production_ready = upstream.production_ready
        self.receipt_path = receipt_path
        self.last_receipt = None

    def submit(self, sequence: int, record: dict) -> dict:
        ack = self.upstream.submit(sequence, record)
        self.identity.check_ack(ack, sequence, record["record_hash"])
        # A failed write also fails the test; success requires retained evidence.
        self.receipt_path.write_text(json.dumps(ack, sort_keys=True) + "\n")
        self.receipt_path.chmod(0o600)
        self.last_receipt = ack
        return ack

    def completion(self, session: str, audit: dict) -> dict:
        if (session != self.identity.session or audit.get("valid") is not True
                or type(audit.get("records")) is not int or audit["records"] < 1
                or self.last_receipt is None):
            raise AnchorError("missing or mismatched completion audit evidence")
        self.identity.check_ack(self.last_receipt, audit["records"], audit.get("head_hash"))
        return dict(self.last_receipt)
