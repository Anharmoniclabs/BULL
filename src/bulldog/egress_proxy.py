from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import threading
import urllib.parse
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


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *, hostname: str, ip: str, port: int, timeout: float):
        self._bull_ip = ip
        super().__init__(host=hostname, port=port, timeout=timeout)

    def connect(self) -> None:
        self.sock = socket.create_connection((self._bull_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *, hostname: str, ip: str, port: int, timeout: float):
        self._bull_hostname = hostname
        self._bull_ip = ip
        context = ssl.create_default_context()
        super().__init__(host=hostname, port=port, timeout=timeout, context=context)

    def connect(self) -> None:
        raw = socket.create_connection((self._bull_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self._bull_hostname)


class EgressBroker:
    """Host-side controlled egress gateway with pinned DNS/TLS and peer auth."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        allowed_hosts: set[str] | frozenset[str],
        allowed_methods: set[str] | frozenset[str] = frozenset({"GET", "HEAD"}),
        require_https: bool = True,
        max_response_bytes: int = 1024 * 1024,
        timeout: float = 8.0,
        audit: Callable[[dict], None] | None = None,
        trace_verifier: RuntimeTraceVerifier | None = None,
        allowed_peer_uids: set[int] | frozenset[int] | None = None,
        require_peer_credentials: bool = False,
    ):
        self.trace = trace_verifier if trace_verifier is not None else RuntimeTraceVerifier()
        self.socket_path = Path(socket_path)
        self.allowed_hosts = frozenset(host.lower().rstrip(".") for host in allowed_hosts)
        if self.allowed_hosts:
            self.trace.emit("GrantBroker")
        self.allowed_methods = frozenset(method.upper() for method in allowed_methods)
        self.require_https = bool(require_https)
        self.max_response_bytes = int(max_response_bytes)
        self.timeout = float(timeout)
        self.audit = audit
        self.require_peer_credentials = bool(require_peer_credentials)
        self.allowed_peer_uids = frozenset(
            int(uid) for uid in (
                allowed_peer_uids
                if allowed_peer_uids is not None
                else ({os.getuid()} if self.require_peer_credentials else set())
            )
        )
        if self.require_peer_credentials and not self.allowed_peer_uids:
            raise EgressError("peer credential enforcement requires a UID allowlist")
        self.peer_auth_enforced = self.require_peer_credentials
        self._server = None
        self._thread = None
        self._stop = threading.Event()

    def start(self):
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
            self._thread.join(timeout=2)
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
                self._handle(conn)

    def _authorize_peer(self, conn: socket.socket) -> tuple[int, int, int] | None:
        if not self.require_peer_credentials:
            return None
        if not hasattr(socket, "SO_PEERCRED"):
            raise EgressDenied("SO_PEERCRED is unavailable on this platform")
        raw = conn.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", raw)
        if uid not in self.allowed_peer_uids:
            raise EgressDenied("egress broker peer UID is not authorized")
        return int(pid), int(uid), int(gid)

    def _handle(self, conn):
        try:
            peer = self._authorize_peer(conn)
            request = json.loads(self._read_line(conn))
            method = str(request.get("method", "GET")).upper()
            url = str(request.get("url", ""))
            response = self.fetch(method=method, url=url)
            payload = {
                "ok": True,
                "status": response.status,
                "headers": response.headers,
                "body_hex": response.body.hex(),
            }
            event = {
                "event": "egress",
                "allowed": True,
                "method": method,
                "url": url,
                "status": response.status,
            }
            if peer is not None:
                event["peer_pid"], event["peer_uid"], event["peer_gid"] = peer
            self._emit(event)
        except Exception as exc:
            payload = {"ok": False, "error": str(exc)}
            self._emit({"event": "egress", "allowed": False, "error": str(exc)})
        conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))

    def fetch(self, *, method: str, url: str) -> EgressResponse:
        method = method.upper()
        if method not in self.allowed_methods:
            raise EgressDenied("HTTP method is not granted")

        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise EgressDenied("unsupported URL scheme")
        if self.require_https and parsed.scheme != "https":
            raise EgressDenied("HTTPS is required")
        if parsed.username or parsed.password:
            raise EgressDenied("URL credentials are forbidden")

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if hostname not in self.allowed_hosts:
            raise EgressDenied("destination host is not granted")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = self._resolve_public_addresses(hostname, port)
        pinned_ip = addresses[0]
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if parsed.scheme == "https":
            connection = _PinnedHTTPSConnection(
                hostname=hostname,
                ip=pinned_ip,
                port=port,
                timeout=self.timeout,
            )
        else:
            connection = _PinnedHTTPConnection(
                hostname=hostname,
                ip=pinned_ip,
                port=port,
                timeout=self.timeout,
            )

        try:
            connection.request(
                method,
                path,
                headers={
                    "Host": hostname,
                    "User-Agent": "BULL-EgressBroker/3",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise EgressDenied("redirects are disabled and require reauthorization")

            body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise EgressDenied("response exceeded size limit")

            result = EgressResponse(
                status=int(response.status),
                headers={str(k): str(v) for k, v in response.getheaders()},
                body=body,
            )
            self.trace.emit("BrokerEgress")
            return result
        except EgressDenied:
            raise
        except Exception as exc:
            raise EgressError(str(exc))
        finally:
            connection.close()

    @staticmethod
    def _resolve_public_addresses(hostname: str, port: int) -> tuple[str, ...]:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not infos:
            raise EgressDenied("hostname did not resolve")

        addresses = set()
        for info in infos:
            raw = info[4][0].split("%", 1)[0]
            address = ipaddress.ip_address(raw)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                raise EgressDenied(
                    "destination resolved to non-public address: " f"{address}"
                )
            addresses.add(str(address))

        if not addresses:
            raise EgressDenied("hostname did not resolve to a public address")
        return tuple(sorted(addresses))

    @staticmethod
    def _validate_public_destination(hostname: str, port: int) -> None:
        EgressBroker._resolve_public_addresses(hostname, port)

    @staticmethod
    def _read_line(conn, limit: int = 32768) -> str:
        data = bytearray()
        while len(data) < limit:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
        if len(data) >= limit:
            raise EgressError("broker request too large")
        return bytes(data).split(b"\n", 1)[0].decode("utf-8")

    def _emit(self, event):
        if self.audit is not None:
            self.audit(dict(event))


def broker_fetch(
    *,
    socket_path: str | Path,
    url: str,
    method: str = "GET",
    timeout: float = 10.0,
) -> EgressResponse:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(socket_path))
        client.sendall(
            (json.dumps({"method": method, "url": url}) + "\n").encode("utf-8")
        )
        response = json.loads(EgressBroker._read_line(client))
        if not response.get("ok"):
            raise EgressDenied(response.get("error", "egress request denied"))
        return EgressResponse(
            status=int(response["status"]),
            headers={str(k): str(v) for k, v in response.get("headers", {}).items()},
            body=bytes.fromhex(response["body_hex"]),
        )
    finally:
        client.close()
