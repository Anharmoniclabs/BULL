"""The contained agent's only route off the machine: model-provider HTTPS.

A managed session has no network interface except loopback. Its client reaches
the model provider through ``HTTPS_PROXY`` on 127.0.0.1, which an in-namespace
forwarder connects to this relay's Unix socket. The relay accepts only
``CONNECT <allowlisted-host>:443``, resolves the name itself and refuses
non-public answers, and records every decision. TLS stays end to end between
client and provider; the relay never sees request contents.

The provider channel is still a data path: anything the model can read, it can
send to its provider. That is inherent in using a hosted model and is stated
in the session coverage rather than hidden.
"""

from __future__ import annotations

import json
import os
import select
import socket
import threading
import time
from typing import Iterable

from .public_address import is_public

HEAD_LIMIT = 8192
MAX_TUNNELS = 64  # Concurrent tunnels; a session cannot exhaust host threads.
IDLE_SECONDS = 600
CONNECT_TIMEOUT = 15


def _read_head(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > HEAD_LIMIT:
            raise ValueError("request head too large")
        chunk = conn.recv(1024)
        if not chunk:
            raise ValueError("incomplete request head")
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    if rest:
        # A client must wait for 200 before sending TLS; early bytes would
        # otherwise be forwarded without having been part of the decision.
        raise ValueError("data before tunnel establishment")
    return head


def parse_connect(head: bytes, allowed: frozenset[str]) -> tuple[str, str | None]:
    """Return (host, refusal reason or None) for a CONNECT request head."""
    try:
        line = head.decode("ascii").split("\r\n", 1)[0]
        method, target, version = line.split(" ")
    except (UnicodeDecodeError, ValueError):
        return "", "malformed request"
    if method != "CONNECT":
        return "", "only CONNECT to the model provider is available"
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return "", "unsupported protocol"
    host, sep, port = target.rpartition(":")
    host = host.strip("[]").rstrip(".").lower()
    if not sep or port != "443":
        return host, "only port 443 is available"
    if host not in allowed:
        return host, "host is not an allowlisted model provider"
    return host, None


def resolve_public(host: str) -> str:
    for *_, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
        if is_public(sockaddr[0]):
            return sockaddr[0].split("%", 1)[0]
    raise OSError(f"{host} has no public address")


def _open_upstream(host: str, upstream_proxy: tuple[str, int] | None) -> socket.socket:
    if upstream_proxy is None:
        return socket.create_connection((resolve_public(host), 443), CONNECT_TIMEOUT)
    # An operator-configured egress proxy (corporate or sandbox networks)
    # resolves the name itself; the allowlist decision has already been made.
    upstream = socket.create_connection(upstream_proxy, CONNECT_TIMEOUT)
    upstream.sendall(
        f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode("ascii")
    )
    reply = b""
    while b"\r\n\r\n" not in reply:
        chunk = upstream.recv(1024)
        if not chunk or len(reply) > HEAD_LIMIT:
            upstream.close()
            raise OSError("upstream proxy refused the tunnel")
        reply += chunk
    status = reply.split(b"\r\n", 1)[0].split(b" ")
    if len(status) < 2 or status[1] != b"200":
        upstream.close()
        raise OSError("upstream proxy refused the tunnel")
    return upstream


def pump(a: socket.socket, b: socket.socket, idle: float = IDLE_SECONDS) -> tuple[int, int]:
    """Copy both directions until either side closes; returns bytes (a→b, b→a)."""
    counts = {a: 0, b: 0}
    peers = {a: b, b: a}
    open_ = {a, b}
    while open_:
        ready, _, _ = select.select(list(open_), [], [], idle)
        if not ready:
            break
        for src in ready:
            try:
                data = src.recv(65536)
            except OSError:
                data = b""
            if not data:
                open_.discard(src)
                try:
                    peers[src].shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            counts[src] += len(data)
            peers[src].sendall(data)
    return counts[a], counts[b]


class InferenceRelay:
    def __init__(
        self,
        listener: socket.socket,
        allowed_hosts: Iterable[str],
        log_fd: int,
        *,
        upstream_proxy: tuple[str, int] | None = None,
    ):
        self.listener = listener
        self.allowed = frozenset(h.lower().rstrip(".") for h in allowed_hosts)
        self.log_fd = log_fd
        self.upstream_proxy = upstream_proxy
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_TUNNELS)

    def _log(self, **event):
        event["ts"] = round(time.time(), 3)
        line = (json.dumps(event, sort_keys=True) + "\n").encode()
        with self._lock:
            os.write(self.log_fd, line)

    def handle(self, conn: socket.socket) -> None:
        host = ""
        with conn:
            try:
                conn.settimeout(10)
                host, refusal = parse_connect(_read_head(conn), self.allowed)
            except (OSError, ValueError) as exc:
                refusal = str(exc)
            if refusal:
                self._log(event="deny", host=host, reason=refusal)
                try:
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
                return
            try:
                upstream = _open_upstream(host, self.upstream_proxy)
            except OSError as exc:
                self._log(event="deny", host=host, reason=f"upstream: {exc}")
                try:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
                return
            with upstream:
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                conn.settimeout(None)
                self._log(event="allow", host=host)
                sent, received = pump(conn, upstream)
                self._log(event="close", host=host, bytes_up=sent, bytes_down=received)

    def serve_forever(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                self._log(event="deny", host="", reason="tunnel limit reached")
                conn.close()
                continue
            threading.Thread(target=self._bounded, args=(conn,), daemon=True).start()

    def _bounded(self, conn: socket.socket) -> None:
        try:
            self.handle(conn)
        finally:
            self._slots.release()


def forward_loopback(port: int, relay_socket: str) -> None:
    """Inside the sandbox: give the client a normal HTTPS_PROXY on loopback."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(64)

    def bridge(conn):
        with conn:
            try:
                upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                upstream.connect(relay_socket)
            except OSError:
                return
            with upstream:
                pump(conn, upstream)

    while True:
        conn, _ = server.accept()
        threading.Thread(target=bridge, args=(conn,), daemon=True).start()


def parse_proxy_url(value: str | None) -> tuple[str, int] | None:
    if not value:
        return None
    from urllib.parse import urlsplit

    parts = urlsplit(value if "://" in value else "http://" + value)
    if parts.scheme != "http" or not parts.hostname or parts.username:
        raise ValueError("upstream proxy must be http://host:port without credentials")
    return parts.hostname, parts.port or 80


__all__ = [
    "InferenceRelay",
    "forward_loopback",
    "parse_connect",
    "parse_proxy_url",
    "resolve_public",
]

