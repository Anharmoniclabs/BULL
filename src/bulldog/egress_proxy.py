from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
import json
import os
import socket
import threading
import urllib.parse
import urllib.request
from typing import Callable

from .trace_runtime import RuntimeTraceVerifier


class EgressDenied(RuntimeError):
    pass


class EgressError(RuntimeError):
    pass


@dataclass(frozen=True)
class EgressResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class _NoRedirect(
    urllib.request.HTTPRedirectHandler
):
    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        raise EgressDenied(
            "redirects are disabled"
        )


class EgressBroker:
    """
    Host-side controlled egress gateway.

    Sandbox direct network remains unavailable.
    """

    def __init__(
        self,
        socket_path: str | Path,
        *,
        allowed_hosts: set[str] | frozenset[str],
        allowed_methods: set[str] | frozenset[str] = frozenset(
            {"GET", "HEAD"}
        ),
        require_https: bool = True,
        max_response_bytes: int = 1024 * 1024,
        timeout: float = 8.0,
        audit: Callable[[dict], None] | None = None,
        trace_verifier: RuntimeTraceVerifier | None = None,
    ):

        self.trace = (
            trace_verifier
            if trace_verifier is not None
            else RuntimeTraceVerifier()
        )

        self.socket_path = Path(
            socket_path
        )

        self.allowed_hosts = frozenset(
            host.lower().rstrip(".")
            for host in allowed_hosts
        )

        if self.allowed_hosts:
            self.trace.emit(
                "GrantBroker"
            )



        self.allowed_methods = frozenset(
            method.upper()
            for method in allowed_methods
        )

        self.require_https = bool(
            require_https
        )

        self.max_response_bytes = int(
            max_response_bytes
        )

        self.timeout = float(
            timeout
        )

        self.audit = audit

        self._server = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):

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

        server.listen(
            16
        )

        server.settimeout(
            0.25
        )

        self._server = server
        self._stop.clear()

        self._thread = threading.Thread(
            target=self._serve,
            name="bull-egress-broker",
            daemon=True,
        )

        self._thread.start()

    def stop(self):

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

    def _serve(self):

        assert self._server is not None

        while not self._stop.is_set():

            try:
                conn, _ = self._server.accept()

            except socket.timeout:
                continue

            except OSError:
                break

            with conn:
                self._handle(
                    conn
                )

    def _handle(
        self,
        conn,
    ):

        try:

            request = json.loads(
                self._read_line(
                    conn
                )
            )

            method = str(
                request.get(
                    "method",
                    "GET",
                )
            ).upper()

            url = str(
                request.get(
                    "url",
                    "",
                )
            )

            response = self.fetch(
                method=method,
                url=url,
            )

            payload = {
                "ok": True,
                "status": response.status,
                "headers": response.headers,
                "body_hex": response.body.hex(),
            }

            self._emit({
                "event": "egress",
                "allowed": True,
                "method": method,
                "url": url,
                "status": response.status,
            })

        except Exception as exc:

            payload = {
                "ok": False,
                "error": str(exc),
            }

            self._emit({
                "event": "egress",
                "allowed": False,
                "error": str(exc),
            })

        conn.sendall(
            (
                json.dumps(
                    payload
                )
                + "\n"
            ).encode(
                "utf-8"
            )
        )

    def fetch(
        self,
        *,
        method: str,
        url: str,
    ) -> EgressResponse:

        method = method.upper()

        if method not in self.allowed_methods:
            raise EgressDenied(
                "HTTP method is not granted"
            )

        parsed = urllib.parse.urlsplit(
            url
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            raise EgressDenied(
                "unsupported URL scheme"
            )

        if (
            self.require_https
            and parsed.scheme != "https"
        ):
            raise EgressDenied(
                "HTTPS is required"
            )

        if (
            parsed.username
            or parsed.password
        ):
            raise EgressDenied(
                "URL credentials are forbidden"
            )

        hostname = (
            parsed.hostname
            or ""
        ).lower().rstrip(".")

        if hostname not in self.allowed_hosts:
            raise EgressDenied(
                "destination host is not granted"
            )

        port = (
            parsed.port
            or (
                443
                if parsed.scheme == "https"
                else 80
            )
        )

        self._validate_public_destination(
            hostname,
            port,
        )

        request = urllib.request.Request(
            url,
            method=method,
            headers={
                "User-Agent":
                    "BULL-EgressBroker/1",
                "Accept":
                    "*/*",
            },
        )

        opener = urllib.request.build_opener(
            _NoRedirect()
        )

        try:

            with opener.open(
                request,
                timeout=self.timeout,
            ) as response:

                body = response.read(
                    self.max_response_bytes
                    + 1
                )

                if len(body) > self.max_response_bytes:
                    raise EgressDenied(
                        "response exceeded size limit"
                    )

                headers = {
                    str(k): str(v)
                    for k, v
                    in response.headers.items()
                }

                result = EgressResponse(
                    status=int(
                        response.status
                    ),
                    headers=headers,
                    body=body,
                )

                self.trace.emit(
                    "BrokerEgress"
                )

                return result

        except EgressDenied:
            raise

        except Exception as exc:
            raise EgressError(
                str(exc)
            )

    @staticmethod
    def _validate_public_destination(
        hostname: str,
        port: int,
    ) -> None:

        infos = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )

        if not infos:
            raise EgressDenied(
                "hostname did not resolve"
            )

        addresses = set()

        for info in infos:

            raw = info[4][0].split(
                "%",
                1,
            )[0]

            addresses.add(
                ipaddress.ip_address(
                    raw
                )
            )

        for address in addresses:

            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                raise EgressDenied(
                    "destination resolved to "
                    f"non-public address: {address}"
                )

    @staticmethod
    def _read_line(
        conn,
        limit: int = 32768,
    ) -> str:

        data = bytearray()

        while len(data) < limit:

            chunk = conn.recv(
                4096
            )

            if not chunk:
                break

            data.extend(
                chunk
            )

            if b"\n" in chunk:
                break

        if len(data) >= limit:
            raise EgressError(
                "broker request too large"
            )

        return bytes(
            data
        ).split(
            b"\n",
            1,
        )[0].decode(
            "utf-8"
        )

    def _emit(
        self,
        event,
    ):

        if self.audit is not None:
            self.audit(
                dict(
                    event
                )
            )


def broker_fetch(
    *,
    socket_path: str | Path,
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
) -> EgressResponse:

    client = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )

    client.settimeout(
        timeout
    )

    try:

        client.connect(
            str(
                socket_path
            )
        )

        client.sendall(
            (
                json.dumps({
                    "method": method,
                    "url": url,
                })
                + "\n"
            ).encode(
                "utf-8"
            )
        )

        raw = EgressBroker._read_line(
            client
        )

        response = json.loads(
            raw
        )

        if not response.get(
            "ok"
        ):
            raise EgressDenied(
                response.get(
                    "error",
                    "egress request denied",
                )
            )

        return EgressResponse(
            status=int(
                response[
                    "status"
                ]
            ),
            headers={
                str(k): str(v)
                for k, v
                in response.get(
                    "headers",
                    {}
                ).items()
            },
            body=bytes.fromhex(
                response[
                    "body_hex"
                ]
            ),
        )

    finally:

        client.close()
