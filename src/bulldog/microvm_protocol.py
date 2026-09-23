"""Bounded, authenticated, ordered messages for one trusted MicroVM session."""
from __future__ import annotations

import os
import re
import select
import time

from .anchor_service import AnchorError, MAX_FRAME, authenticate, canonical, decode, verify


class RemoteSessionError(AnchorError):
    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__('guest session failed: ' + str(payload.get('type', 'unknown')) + ': ' + str(payload.get('detail', '')))


class SessionChannel:
    def __init__(self, fd: int, session: str, key: bytes, *, side: str, timeout: float = 10):
        if not re.fullmatch(r"[a-f0-9]{64}", session) or len(key) < 32:
            raise AnchorError("invalid control session identity")
        if side not in {"host", "guest"} or not 0 < timeout <= 120:
            raise AnchorError("invalid control channel configuration")
        self.fd, self.session, self.key = fd, session, key
        self.side, self.timeout = side, timeout
        self.sent = self.received = 0
        self.failed = False
        self.executed = False
        os.set_inheritable(fd, False)
        os.set_blocking(fd, False)

    def _transfer(self, *, data: bytes | None = None, length: int = 0) -> bytes:
        deadline = time.monotonic() + self.timeout
        result = bytearray()
        position = 0
        while position < (len(data) if data is not None else length):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AnchorError("control deadline exceeded")
            readable, writable, _ = select.select([self.fd] if data is None else [],
                                                   [self.fd] if data is not None else [], [], remaining)
            if not (readable or writable):
                raise AnchorError("control deadline exceeded")
            try:
                if data is not None:
                    count = os.write(self.fd, data[position:])
                else:
                    chunk = os.read(self.fd, length - position)
                    count = len(chunk)
                    result.extend(chunk)
            except BlockingIOError:
                continue
            if count == 0:
                raise AnchorError("control channel disconnected")
            position += count
        return bytes(result)

    def send(self, kind: str, payload: dict) -> None:
        if self.failed:
            raise AnchorError("control channel is unusable after failure")
        try:
            self._send(kind, payload)
        except Exception:
            self.failed = True
            raise

    def _send(self, kind: str, payload: dict) -> None:
        if kind == "execute" and (self.side != "host" or self.executed):
            raise AnchorError("one-shot execution authority already used or wrong direction")
        if kind not in {"ready", "execute", "result", "error"} or not isinstance(payload, dict):
            raise AnchorError("unsupported control operation")
        message = authenticate({"version": 1, "session": self.session,
                                "sequence": self.sent + 1, "kind": kind, "payload": payload},
                               self.key, purpose="control-" + self.side)
        encoded = canonical(message)
        if len(encoded) > MAX_FRAME:
            raise AnchorError("control frame exceeds limit")
        self._transfer(data=len(encoded).to_bytes(4, "big") + encoded)
        self.sent += 1
        if kind == "execute":
            self.executed = True

    def receive(self, expected_kind: str) -> dict:
        if self.failed:
            raise AnchorError("control channel is unusable after failure")
        try:
            return self._receive(expected_kind)
        except Exception:
            self.failed = True
            raise

    def _receive(self, expected_kind: str) -> dict:
        if expected_kind == "execute" and (self.side != "guest" or self.executed):
            raise AnchorError("one-shot execution authority already used or wrong direction")
        length = int.from_bytes(self._transfer(length=4), "big")
        if not 0 < length <= MAX_FRAME:
            raise AnchorError("invalid control frame length")
        message = decode(self._transfer(length=length))
        peer = "guest" if self.side == "host" else "host"
        verify(message, self.key, purpose="control-" + peer)
        if (set(message) != {"version", "session", "sequence", "kind", "payload", "mac"}
                or type(message["version"]) is not int or message["version"] != 1
                or message["session"] != self.session
                or type(message["sequence"]) is not int or message["sequence"] != self.received + 1
                or message["kind"] not in {expected_kind, 'error'} or not isinstance(message["payload"], dict)):
            raise AnchorError("unexpected control message or session/sequence mismatch")
        self.received += 1
        if message["kind"] == "execute":
            self.executed = True
        if message['kind'] == 'error' and expected_kind != 'error':
            raise RemoteSessionError(message['payload'])
        return message["payload"]
