"""Single-writer lease and attempt accounting outside the agent's workspace.

An interrupted attempt remains uncertain. It is never replayed automatically.
This journal is local authority state, not an exactly-once delivery guarantee.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import time

from .gateway_wire import GatewayDenied


def private_directory(path: Path) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise GatewayDenied("state must be an existing canonical directory")
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise GatewayDenied("state must be authority-owned and mode 0700")
    for parent in path.parents:
        info = parent.stat()
        if info.st_uid not in {0, os.geteuid()} or (
            info.st_mode & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise GatewayDenied("state has an untrusted writable ancestor")
    return path


def private_file(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        os.close(fd)
        raise GatewayDenied("state file must be a private authority-owned regular file")
    return fd


class AgentSession:
    def __init__(self, directory: Path, config: dict, policy_digest: str):
        self.directory = private_directory(directory)
        self.config = config
        self.lock = private_file(directory / "session.lock")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            database = directory / "session.sqlite3"
            os.close(private_file(database))
            self.db = sqlite3.connect(database)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS lease (id TEXT PRIMARY KEY, digest TEXT NOT NULL, used INTEGER NOT NULL, clock REAL NOT NULL)"
            )
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS attempt (id TEXT PRIMARY KEY, tool TEXT NOT NULL, state TEXT NOT NULL)"
            )
            row = self.db.execute("SELECT id, digest FROM lease").fetchone()
            self.previous_instance_used = bool(
                row and self.db.execute("SELECT used FROM lease").fetchone()[0]
            )
            if row is None:
                self.db.execute(
                    "INSERT INTO lease VALUES (?, ?, 0, ?)",
                    (config["session_id"], policy_digest, time.time()),
                )
            elif row != (config["session_id"], policy_digest):
                raise GatewayDenied(
                    "state belongs to another signed lease; use a new private state directory"
                )
            if self.db.execute("SELECT count(*) FROM lease").fetchone()[0] != 1:
                raise GatewayDenied("ambiguous lease state")
            self.db.execute(
                "UPDATE attempt SET state='uncertain' WHERE state='running'"
            )
            self.db.commit()
            self.deadline = time.monotonic() + max(
                0, config["expires_at"] - time.time()
            )
        except BaseException:
            self.close()
            raise

    def close(self):
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None
        if getattr(self, "lock", None) is not None:
            os.close(self.lock)
            self.lock = None

    def check_lease(self):
        now = time.time()
        _, _, used, clock = self.db.execute("SELECT * FROM lease").fetchone()
        if (self.directory / "REVOKED").exists() or (
            self.directory / "REVOKED"
        ).is_symlink():
            raise GatewayDenied("lease revoked by operator")
        if now >= self.config["expires_at"] or time.monotonic() >= self.deadline:
            raise GatewayDenied("lease expired")
        if now + 1 < clock:
            raise GatewayDenied("clock moved backwards")
        if self.previous_instance_used:
            raise GatewayDenied(
                "used lease cannot resume with reset behavioral history; issue a new lease"
            )

    def check(self):
        self.check_lease()
        used = self.db.execute("SELECT used FROM lease").fetchone()[0]
        if self.db.execute(
            "SELECT 1 FROM attempt WHERE state IN ('running','uncertain') LIMIT 1"
        ).fetchone():
            raise GatewayDenied(
                "an attempt has an uncertain outcome; operator review required"
            )
        if used >= self.config["max_calls"]:
            raise GatewayDenied("call budget exhausted")

    def begin(self, call_id: str, name: str):
        self.check()
        with self.db:
            if self.db.execute(
                "SELECT 1 FROM attempt WHERE id=?", (call_id,)
            ).fetchone():
                raise GatewayDenied("call ID already used; no replay")
            self.db.execute(
                "INSERT INTO attempt VALUES (?, ?, 'running')", (call_id, name)
            )
            self.db.execute(
                "UPDATE lease SET used=used+1, clock=max(clock, ?)", (time.time(),)
            )

    def finish(self, call_id: str, state: str):
        if state not in {"completed", "denied", "uncertain", "approval_required"}:
            raise GatewayDenied("invalid outcome")
        with self.db:
            self.db.execute(
                "UPDATE attempt SET state=? WHERE id=? AND state='running'",
                (state, call_id),
            )

    def status(self) -> dict:
        _, _, used, _ = self.db.execute("SELECT * FROM lease").fetchone()
        return {
            "used_calls": used,
            "max_calls": self.config["max_calls"],
            "expires_at": self.config["expires_at"],
            "uncertain_calls": self.db.execute(
                "SELECT count(*) FROM attempt WHERE state IN ('running','uncertain')"
            ).fetchone()[0],
        }
