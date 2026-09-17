from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time
from typing import Callable

from .trace_runtime import RuntimeTraceVerifier


class SecretBrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecretGrant:
    token: str
    allowed_names: frozenset[str]
    expires_at: float
    sandbox_id: str | None = None
    max_uses: int | None = None


class SecretBroker:
    """Host-side in-memory secret broker with optional SO_PEERCRED binding."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        audit: Callable[[dict], None] | None = None,
        trace_verifier: RuntimeTraceVerifier | None = None,
        allowed_peer_uids: set[int] | frozenset[int] | None = None,
        require_peer_credentials: bool = False,
    ):
        self.socket_path = Path(socket_path)
        self.audit = audit
        self.trace = (
            trace_verifier
            if trace_verifier is not None
            else RuntimeTraceVerifier()
        )
        self.require_peer_credentials = bool(require_peer_credentials)
        self.allowed_peer_uids = frozenset(
            int(uid) for uid in (
                allowed_peer_uids
                if allowed_peer_uids is not None
                else ({os.getuid()} if self.require_peer_credentials else set())
            )
        )
        if self.require_peer_credentials and not self.allowed_peer_uids:
            raise SecretBrokerError("peer credential enforcement requires a UID allowlist")
        self.peer_auth_enforced = self.require_peer_credentials

        self._secrets: dict[str, str] = {}
        self._grants: dict[str, SecretGrant] = {}
        self._grant_uses: dict[str, int] = {}
        self._grant_lock = threading.Lock()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def put_secret(self, name: str, value: str) -> None:
        if not name:
            raise ValueError("secret name cannot be empty")
        self._secrets[str(name)] = str(value)

    def issue_grant(
        self,
        *,
        allowed_names: set[str] | frozenset[str],
        ttl_seconds: float = 60.0,
        sandbox_id: str | None = None,
        max_uses: int | None = None,
    ) -> SecretGrant:
        if max_uses is not None and int(max_uses) < 1:
            raise ValueError("max_uses must be >= 1")
        if float(ttl_seconds) <= 0:
            raise ValueError("ttl_seconds must be > 0")

        names = frozenset(str(x) for x in allowed_names)
        unknown = names.difference(self._secrets)
        if unknown:
            raise SecretBrokerError(
                "grant references unknown secrets: " + ", ".join(sorted(unknown))
            )

        token = secrets.token_urlsafe(32)
        grant = SecretGrant(
            token=token,
            allowed_names=names,
            expires_at=time.time() + float(ttl_seconds),
            sandbox_id=str(sandbox_id) if sandbox_id is not None else None,
            max_uses=int(max_uses) if max_uses is not None else None,
        )
        with self._grant_lock:
            self._grants[token] = grant
            self._grant_uses[token] = 0

        self.trace.emit("GrantSecret")
        self._emit({
            "event": "grant_issued",
            "allowed_names": sorted(names),
            "expires_at": grant.expires_at,
            "sandbox_id": grant.sandbox_id,
            "max_uses": grant.max_uses,
        })
        return grant

    def revoke(self, token: str) -> None:
        with self._grant_lock:
            self._grants.pop(token, None)
            self._grant_uses.pop(token, None)
        self._emit({"event": "grant_revoked"})

    def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        server.listen(16)
        server.settimeout(0.25)
        self._server = server
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve,
            name="bull-secret-broker",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                self._handle(conn)

    def _authorize_peer(self, conn: socket.socket) -> tuple[int, int, int] | None:
        if not self.require_peer_credentials:
            return None
        if not hasattr(socket, "SO_PEERCRED"):
            raise SecretBrokerError("SO_PEERCRED is unavailable on this platform")
        raw = conn.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", raw)
        if uid not in self.allowed_peer_uids:
            raise SecretBrokerError("secret broker peer UID is not authorized")
        return int(pid), int(uid), int(gid)

    def _handle(self, conn: socket.socket) -> None:
        try:
            peer = self._authorize_peer(conn)
            request = json.loads(self._read_line(conn))
            if request.get("op") != "get":
                raise SecretBrokerError("unsupported operation")

            token = str(request.get("token", ""))
            name = str(request.get("name", ""))
            sandbox_id_raw = request.get("sandbox_id")
            sandbox_id = (
                str(sandbox_id_raw) if sandbox_id_raw is not None else None
            )
            value = self._authorize_and_get(token, name, sandbox_id=sandbox_id)
            response = {"ok": True, "name": name, "value": value}
            event = {
                "event": "secret_access",
                "name": name,
                "allowed": True,
                "sandbox_id": sandbox_id,
            }
            if peer is not None:
                event["peer_pid"], event["peer_uid"], event["peer_gid"] = peer
            self._emit(event)
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
            self._emit({
                "event": "secret_access",
                "allowed": False,
                "error": str(exc),
            })
        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    def _authorize_and_get(
        self,
        token: str,
        name: str,
        *,
        sandbox_id: str | None = None,
    ) -> str:
        with self._grant_lock:
            grant = None
            stored_key = None
            for stored_token, candidate in self._grants.items():
                if hmac.compare_digest(stored_token, token):
                    grant = candidate
                    stored_key = stored_token
                    break

            if grant is None or stored_key is None:
                raise SecretBrokerError("invalid secret grant")
            if time.time() > grant.expires_at:
                self._grants.pop(stored_key, None)
                self._grant_uses.pop(stored_key, None)
                raise SecretBrokerError("secret grant expired")
            if grant.sandbox_id is not None and sandbox_id != grant.sandbox_id:
                raise SecretBrokerError("secret grant belongs to another sandbox")
            if name not in grant.allowed_names:
                raise SecretBrokerError("secret not granted")

            uses = self._grant_uses.get(stored_key, 0)
            if grant.max_uses is not None and uses >= grant.max_uses:
                raise SecretBrokerError("secret grant usage exhausted")
            try:
                value = self._secrets[name]
            except KeyError:
                raise SecretBrokerError("secret unavailable")
            self._grant_uses[stored_key] = uses + 1

        self.trace.emit("ReturnSecret")
        return value

    @staticmethod
    def _read_line(conn: socket.socket, limit: int = 16384) -> str:
        data = bytearray()
        while len(data) < limit:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
        if len(data) >= limit:
            raise SecretBrokerError("request too large")
        return bytes(data).split(b"\n", 1)[0].decode("utf-8")

    def _emit(self, event: dict) -> None:
        if self.audit is not None:
            self.audit(dict(event))


def request_secret(
    *,
    socket_path: str | Path,
    token: str,
    name: str,
    sandbox_id: str | None = None,
    timeout: float = 3.0,
) -> str:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(socket_path))
        request = {"op": "get", "token": token, "name": name}
        if sandbox_id is not None:
            request["sandbox_id"] = str(sandbox_id)
        client.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = json.loads(SecretBroker._read_line(client))
        if not response.get("ok"):
            raise SecretBrokerError(
                response.get("error", "secret request failed")
            )
        return str(response["value"])
    finally:
        client.close()
