from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hmac
import json
import os
import secrets
import socket
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


class SecretBroker:
    """
    Host-side in-memory secret broker.

    Security properties:
      - secrets are never written to disk by this broker
      - clients cannot enumerate names
      - grants are explicit per secret
      - grants expire
      - bearer tokens are high-entropy random values
      - broker uses AF_UNIX instead of exposing a TCP listener
    """

    def __init__(
        self,
        socket_path: str | Path,
        *,
        audit: Callable[[dict], None] | None = None,
        trace_verifier: RuntimeTraceVerifier | None = None,
    ):
        self.socket_path = Path(socket_path)
        self.audit = audit
        self.trace = (
            trace_verifier
            if trace_verifier is not None
            else RuntimeTraceVerifier()
        )

        self._secrets: dict[str, str] = {}
        self._grants: dict[str, SecretGrant] = {}

        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def put_secret(
        self,
        name: str,
        value: str,
    ) -> None:

        if not name:
            raise ValueError("secret name cannot be empty")

        self._secrets[str(name)] = str(value)

    def issue_grant(
        self,
        *,
        allowed_names: set[str] | frozenset[str],
        ttl_seconds: float = 60.0,
    ) -> SecretGrant:

        names = frozenset(
            str(x)
            for x in allowed_names
        )

        unknown = names.difference(
            self._secrets
        )

        if unknown:
            raise SecretBrokerError(
                "grant references unknown secrets: "
                + ", ".join(sorted(unknown))
            )

        token = secrets.token_urlsafe(32)

        grant = SecretGrant(
            token=token,
            allowed_names=names,
            expires_at=time.time() + ttl_seconds,
        )

        self._grants[token] = grant

        self.trace.emit(
            "GrantSecret"
        )

        self._emit({
            "event": "grant_issued",
            "allowed_names": sorted(names),
            "expires_at": grant.expires_at,
        })

        return grant

    def revoke(
        self,
        token: str,
    ) -> None:
        self._grants.pop(
            token,
            None,
        )

        self._emit({
            "event": "grant_revoked",
        })

    def start(self) -> None:

        self.socket_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

        server = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )

        server.bind(
            str(self.socket_path)
        )

        os.chmod(
            self.socket_path,
            0o600,
        )

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
            self._thread.join(
                timeout=2,
            )

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

    def _handle(
        self,
        conn: socket.socket,
    ) -> None:

        try:
            raw = self._read_line(conn)

            request = json.loads(
                raw
            )

            if request.get("op") != "get":
                raise SecretBrokerError(
                    "unsupported operation"
                )

            token = str(
                request.get(
                    "token",
                    "",
                )
            )

            name = str(
                request.get(
                    "name",
                    "",
                )
            )

            value = self._authorize_and_get(
                token,
                name,
            )

            response = {
                "ok": True,
                "name": name,
                "value": value,
            }

            self._emit({
                "event": "secret_access",
                "name": name,
                "allowed": True,
            })

        except Exception as exc:

            response = {
                "ok": False,
                "error": str(exc),
            }

            self._emit({
                "event": "secret_access",
                "allowed": False,
                "error": str(exc),
            })

        conn.sendall(
            (
                json.dumps(response)
                + "\n"
            ).encode("utf-8")
        )

    def _authorize_and_get(
        self,
        token: str,
        name: str,
    ) -> str:

        grant = None

        # Avoid straightforward token equality timing differences.
        for stored_token, candidate in self._grants.items():

            if hmac.compare_digest(
                stored_token,
                token,
            ):
                grant = candidate
                break

        if grant is None:
            raise SecretBrokerError(
                "invalid secret grant"
            )

        if time.time() > grant.expires_at:

            self._grants.pop(
                grant.token,
                None,
            )

            raise SecretBrokerError(
                "secret grant expired"
            )

        if name not in grant.allowed_names:
            raise SecretBrokerError(
                "secret not granted"
            )

        try:
            value = self._secrets[name]

            self.trace.emit(
                "ReturnSecret"
            )

            return value

        except KeyError:
            raise SecretBrokerError(
                "secret unavailable"
            )

    @staticmethod
    def _read_line(
        conn: socket.socket,
        limit: int = 16384,
    ) -> str:

        data = bytearray()

        while len(data) < limit:

            chunk = conn.recv(4096)

            if not chunk:
                break

            data.extend(chunk)

            if b"\n" in chunk:
                break

        if len(data) >= limit:
            raise SecretBrokerError(
                "request too large"
            )

        return bytes(data).split(
            b"\n",
            1,
        )[0].decode("utf-8")

    def _emit(
        self,
        event: dict,
    ) -> None:

        if self.audit is not None:
            self.audit(dict(event))


def request_secret(
    *,
    socket_path: str | Path,
    token: str,
    name: str,
    timeout: float = 3.0,
) -> str:
    """
    Minimal sandbox-side client.
    """

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        timeout
    )

    try:
        client.connect(
            str(socket_path)
        )

        request = {
            "op": "get",
            "token": token,
            "name": name,
        }

        client.sendall(
            (
                json.dumps(request)
                + "\n"
            ).encode("utf-8")
        )

        raw = SecretBroker._read_line(
            client
        )

        response = json.loads(
            raw
        )

        if not response.get("ok"):
            raise SecretBrokerError(
                response.get(
                    "error",
                    "secret request failed",
                )
            )

        return str(
            response["value"]
        )

    finally:
        client.close()
