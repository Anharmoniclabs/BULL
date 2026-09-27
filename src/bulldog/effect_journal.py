"""Durable host-owned journal for consequential external effects.

This component provides at-most-once *dispatch* and explicit reconciliation.
Exactly-once delivery requires an idempotency contract at the external service;
BULL never converts an uncertain outcome into an automatic retry.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Callable


class EffectJournalError(RuntimeError):
    pass


@dataclass(frozen=True)
class EffectRecord:
    key: str
    digest: str
    state: str
    attempts: int
    external_receipt: str | None


def _canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


class DurableEffectJournal:
    """Consume an effect key before dispatch and require host reconciliation."""

    def __init__(self, directory: str | Path, *, audit: Callable[[str, dict], object]):
        self.root = Path(directory).resolve(strict=True)
        st = self.root.stat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
                or st.st_mode & 0o077):
            raise EffectJournalError("effect journal directory must be owner-only mode 0700")
        self.audit = audit
        self.path = self.root / "effects.sqlite3"
        if self.path.exists() and self.path.is_symlink():
            raise EffectJournalError("effect journal database cannot be a symlink")
        with self._connect() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS effects (
                effect_key TEXT PRIMARY KEY,
                body_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                attempts INTEGER NOT NULL,
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL,
                external_receipt TEXT);
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _key(key: str) -> str:
        if not isinstance(key, str) or not 16 <= len(key) <= 128:
            raise EffectJournalError("host idempotency key must be 16..128 characters")
        if any(not (c.isalnum() or c in "-_.:") for c in key):
            raise EffectJournalError("host idempotency key contains unsupported characters")
        return key

    def prepare(self, key: str, effect: dict) -> EffectRecord:
        """Persist intent. Reusing a key for changed bytes always fails closed."""
        key = self._key(key)
        body_digest = hashlib.sha256(_canonical(effect)).hexdigest()
        now = int(time.time())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM effects WHERE effect_key=?", (key,)).fetchone()
            if row is None:
                self.audit("effect.intent_prepared", {"effect_key": key, "body_digest": body_digest})
                db.execute("INSERT INTO effects VALUES (?, ?, 'prepared', 0, ?, ?, NULL)",
                           (key, body_digest, now, now))
                db.commit()
                return EffectRecord(key, body_digest, "prepared", 0, None)
            db.rollback()
            if row["body_digest"] != body_digest:
                raise EffectJournalError("idempotency key was already bound to different effect bytes")
            return EffectRecord(key, body_digest, row["state"], row["attempts"], row["external_receipt"])

    def begin(self, key: str, effect: dict) -> EffectRecord:
        """Consume dispatch authority once, before any external call."""
        prepared = self.prepare(key, effect)
        if prepared.state != "prepared":
            raise EffectJournalError(f"effect is {prepared.state}; automatic dispatch is forbidden")
        now = int(time.time())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE effects SET state='inflight', attempts=1, updated=? "
                "WHERE effect_key=? AND state='prepared' AND attempts=0",
                (now, key),
            ).rowcount
            if changed != 1:
                db.rollback()
                raise EffectJournalError("effect dispatch authority was consumed concurrently")
            self.audit("effect.dispatch_started", {"effect_key": key, "body_digest": prepared.digest})
            db.commit()
        return EffectRecord(key, prepared.digest, "inflight", 1, None)

    def finish(self, key: str, *, receipt: str) -> EffectRecord:
        if not isinstance(receipt, str) or not receipt or len(receipt) > 4096:
            raise EffectJournalError("bounded external receipt required")
        now = int(time.time())
        receipt_digest = hashlib.sha256(receipt.encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM effects WHERE effect_key=?", (self._key(key),)).fetchone()
            if row is None or row["state"] != "inflight":
                db.rollback()
                raise EffectJournalError("only an inflight effect can be confirmed")
            self.audit("effect.external_confirmed", {"effect_key": key,
                                                       "receipt_digest": receipt_digest})
            db.execute("UPDATE effects SET state='confirmed', updated=?, external_receipt=? "
                       "WHERE effect_key=?", (now, receipt_digest, key))
            db.commit()
            return EffectRecord(key, row["body_digest"], "confirmed", row["attempts"], receipt_digest)

    def mark_uncertain(self, key: str, *, reason: str) -> EffectRecord:
        if not isinstance(reason, str) or not reason or len(reason) > 1024:
            raise EffectJournalError("bounded uncertainty reason required")
        now = int(time.time())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM effects WHERE effect_key=?", (self._key(key),)).fetchone()
            if row is None or row["state"] != "inflight":
                db.rollback()
                raise EffectJournalError("only an inflight effect can become uncertain")
            self.audit("effect.outcome_uncertain", {"effect_key": key,
                                                     "reason_digest": hashlib.sha256(reason.encode()).hexdigest()})
            db.execute("UPDATE effects SET state='uncertain', updated=? WHERE effect_key=?", (now, key))
            db.commit()
            return EffectRecord(key, row["body_digest"], "uncertain", row["attempts"], None)

    def reconcile(self, key: str, *, observed: str, receipt: str | None = None) -> EffectRecord:
        """Record a host observation; never execute or retry the effect."""
        if observed not in {"confirmed", "not_observed", "unknown"}:
            raise EffectJournalError("invalid reconciliation observation")
        if observed == "confirmed" and (not receipt or len(receipt) > 4096):
            raise EffectJournalError("confirmed reconciliation requires a bounded receipt")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM effects WHERE effect_key=?", (self._key(key),)).fetchone()
            if row is None or row["state"] not in {"uncertain", "inflight"}:
                db.rollback()
                raise EffectJournalError("effect is not awaiting reconciliation")
            state = "confirmed" if observed == "confirmed" else "not_observed" if observed == "not_observed" else "uncertain"
            receipt_digest = hashlib.sha256(receipt.encode()).hexdigest() if receipt else None
            self.audit("effect.reconciled", {"effect_key": key, "observation": observed,
                                             "receipt_digest": receipt_digest})
            db.execute("UPDATE effects SET state=?, updated=?, external_receipt=? WHERE effect_key=?",
                       (state, int(time.time()), receipt_digest, key))
            db.commit()
            return EffectRecord(key, row["body_digest"], state, row["attempts"], receipt_digest)
