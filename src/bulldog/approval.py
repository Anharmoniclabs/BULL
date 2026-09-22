"""Durable one-use consequential-action approval, owned by the trusted host.

Pending requests grant no authority. An approval is an additional requirement,
never an override of the reference monitor. The database must not be exposed to
workloads. A consumed request is never automatically retried after interruption.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Callable

from .approval_crypto import ApprovalError, validate_public_key, verify_hardware_signature

FORMAT = "bull-human-approval-v1"
OPERATIONS = frozenset({"secret.read", "network.request", "publish", "send", "delete", "access.change", "security.change"})


def canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ApprovalProof:
    request_id: str
    credential_id: str
    signature: bytes


class ApprovalRequired(ApprovalError):
    def __init__(self, request: dict):
        self.request = request
        super().__init__("credentialed approval required: " + request["request_id"])


def validate_config(config: dict) -> dict:
    if not isinstance(config, dict) or set(config) != {"state_directory", "credentials", "routine_egress_urls", "ttl_seconds"}:
        raise ApprovalError("invalid human_approval configuration fields")
    ttl = config["ttl_seconds"]
    if type(ttl) is not int or not 30 <= ttl <= 600:
        raise ApprovalError("approval lifetime must be 30..600 seconds")
    if not isinstance(config["state_directory"], str) or not Path(config["state_directory"]).is_absolute():
        raise ApprovalError("approval state directory must be absolute")
    credentials = config["credentials"]
    if not isinstance(credentials, dict) or not 1 <= len(credentials) <= 32:
        raise ApprovalError("one to 32 enrolled credentials required")
    for identity, public_key in credentials.items():
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", identity):
            raise ApprovalError("invalid credential identity")
        if not isinstance(public_key, str):
            raise ApprovalError("invalid enrolled key")
        validate_public_key(public_key)
    from urllib.parse import urlsplit
    urls = config["routine_egress_urls"]
    if not isinstance(urls, list) or len(urls) > 256:
        raise ApprovalError("routine egress list must be bounded")
    for url in urls:
        if not isinstance(url, str) or len(url) > 4096:
            raise ApprovalError("invalid routine URL")
        if any(ord(c) <= 32 or ord(c) == 127 for c in url):
            raise ApprovalError("invalid routine URL characters")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ApprovalError("routine egress requires exact HTTPS URLs without query or fragment")
    return json.loads(json.dumps(config))


def binding_for(action, *, operation: str, parameters: dict, policy_digest: str, session_id: str) -> dict:
    if operation not in OPERATIONS:
        raise ApprovalError("unsupported consequential operation")
    if not session_id or not policy_digest:
        raise ApprovalError("missing trusted session/policy identity")
    value = {
        "operation": operation,
        "target": action.resource,
        "actor": action.actor,
        "domain_id": action.metadata.get("domain_id", ""),
        "root_domain_id": action.metadata.get("root_domain_id", ""),
        "security_context_id": action.metadata.get("security_context_id", ""),
        "session_id": session_id,
        "policy_digest": policy_digest,
        "capability": action.capability.value,
        "granted_capabilities": sorted(x.value for x in action.granted_capabilities),
        "parent_capabilities": None if action.parent_capabilities is None else sorted(x.value for x in action.parent_capabilities),
        "provenance": [x.value for x in action.provenance],
        "parameters": parameters,
    }
    if len(canonical_bytes(value)) > 32768:
        raise ApprovalError("approval action exceeds size limit")
    return value


class ApprovalGate:
    def __init__(self, config: dict, *, audit: Callable[[str, dict], str], policy_digest: str):
        self.config = validate_config(config)
        self.audit = audit
        self.policy_digest = policy_digest
        self.root = Path(self.config["state_directory"])
        # Existing private directory, not automatic provisioning in a workspace.
        if self.root.resolve(strict=True) != self.root or self.root.is_symlink():
            raise ApprovalError("approval directory must be canonical without symlinks")
        st = self.root.stat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise ApprovalError("approval directory must be owned by service UID and mode 0700")
        self.path = self.root / "approvals.sqlite3"
        if self.path.exists() or self.path.is_symlink():
            st = self.path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise ApprovalError("approval database must be private regular file")
        else:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                  id TEXT PRIMARY KEY, binding TEXT NOT NULL, message BLOB NOT NULL,
                  issued INTEGER NOT NULL, expires INTEGER NOT NULL,
                  state TEXT NOT NULL, credential TEXT, outcome TEXT);
                CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY, highwater INTEGER NOT NULL);
                INSERT OR IGNORE INTO clock VALUES (1, 0);
            """)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def _now(db) -> int:
        now = int(time.time())
        previous = db.execute("SELECT highwater FROM clock WHERE id=1").fetchone()[0]
        if now < previous:
            raise ApprovalError("clock moved backwards; approval stopped")
        db.execute("UPDATE clock SET highwater=? WHERE id=1", (now,))
        return now

    def request(self, binding: dict) -> dict:
        if binding.get("policy_digest") != self.policy_digest:
            raise ApprovalError("approval policy binding mismatch")
        encoded = canonical_bytes(binding)
        if len(encoded) > 32768:
            raise ApprovalError("approval binding too large")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = self._now(db)
            # Bounded storage; operators archive only after all requests expire.
            if db.execute("SELECT count(*) FROM requests").fetchone()[0] >= 10000:
                raise ApprovalError("approval record budget reached")
            request_id = secrets.token_hex(32)
            request = {"format": FORMAT, "request_id": request_id, "issued_at": now,
                       "expires_at": now + self.config["ttl_seconds"], "action": binding}
            message = canonical_bytes(request)
            self.audit("approval.requested", {"request_id": request_id,
                       "binding_digest": digest(encoded), "operation": binding["operation"]})
            db.execute("INSERT INTO requests VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)",
                       (request_id, digest(encoded), message, now, request["expires_at"]))
            db.commit()
        return request

    def consume(self, binding: dict, proof: ApprovalProof | None) -> str:
        if proof is None:
            raise ApprovalRequired(self.request(binding))
        if not isinstance(proof, ApprovalProof):
            raise ApprovalError("credential proof required; text approval is invalid")
        key = self.config["credentials"].get(proof.credential_id)
        if key is None:
            raise ApprovalError("credential is unknown or revoked")
        expected = digest(canonical_bytes(binding))
        with self._connect() as db:
            row = db.execute("SELECT * FROM requests WHERE id=?", (proof.request_id,)).fetchone()
        if row is None or row["state"] != "pending" or row["binding"] != expected:
            raise ApprovalError("approval is missing, changed, cancelled, or already consumed")
        if binding.get("policy_digest") != self.policy_digest:
            raise ApprovalError("approval policy changed")
        verify_hardware_signature(bytes(row["message"]), proof.signature, key)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = self._now(db)
            row = db.execute("SELECT * FROM requests WHERE id=?", (proof.request_id,)).fetchone()
            if row is None or row["state"] != "pending" or row["binding"] != expected:
                raise ApprovalError("approval has already been consumed or cancelled")
            if now >= row["expires"] or now < row["issued"]:
                raise ApprovalError("approval has expired or clock is invalid")
            # Commit consumption BEFORE effect/audit delivery. Failure afterwards
            # leaves a terminal, uncertain request, never a replayable approval.
            db.execute("UPDATE requests SET state='consumed', credential=?, outcome='uncertain' WHERE id=?",
                       (proof.credential_id, proof.request_id))
            db.commit()
        self.audit("approval.consumed", {"request_id": proof.request_id,
                   "binding_digest": expected, "credential_id": proof.credential_id})
        return proof.request_id

    def finish(self, request_id: str, outcome: str) -> None:
        if outcome not in {"completed", "uncertain"}:
            raise ApprovalError("invalid approval outcome")
        self.audit("approval.outcome", {"request_id": request_id, "outcome": outcome})
        with self._connect() as db:
            db.execute("UPDATE requests SET outcome=? WHERE id=? AND state='consumed'", (outcome, request_id))

    def cancel(self, request_id: str) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.audit("approval.cancelled", {"request_id": request_id})
            db.execute("UPDATE requests SET state='cancelled' WHERE id=? AND state='pending'", (request_id,))
            db.commit()

    def inspect(self, request_id: str) -> dict:
        with self._connect() as db:
            row = db.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
        if row is None:
            raise ApprovalError("unknown approval request")
        return {"request": json.loads(row["message"]), "state": row["state"],
                "credential_id": row["credential"], "outcome": row["outcome"]}
