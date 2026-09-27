"""Bounded, unambiguous messages for the local agent connector."""

from __future__ import annotations

import json
import socket
import time

MAX_REQUEST = 32 * 1024
MAX_RESPONSE = 192 * 1024


class GatewayDenied(ValueError):
    pass


def decode_message(raw: bytes, *, limit: int = MAX_REQUEST) -> dict:
    if not raw or len(raw) > limit:
        raise GatewayDenied("message size limit")

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise GatewayDenied("duplicate JSON key")
            value[key] = item
        return value

    def constant(_):
        raise GatewayDenied("non-finite JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GatewayDenied("invalid JSON message") from exc
    if not isinstance(value, dict):
        raise GatewayDenied("message must be an object")
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 12 or nodes > 2048:
            raise GatewayDenied("JSON structure limit")
        if isinstance(item, dict):
            pending.extend((x, depth + 1) for x in item.values())
        elif isinstance(item, list):
            pending.extend((x, depth + 1) for x in item)
        elif isinstance(item, str):
            try:
                item.encode("utf-8", "strict")
            except UnicodeError as exc:
                raise GatewayDenied("invalid Unicode") from exc
        elif isinstance(item, float):
            import math

            if not math.isfinite(item):
                raise GatewayDenied("non-finite JSON number")
    return value


def read_frame(conn: socket.socket, *, limit: int, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) <= limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GatewayDenied("message deadline exceeded")
        conn.settimeout(remaining)
        chunk = conn.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            raise GatewayDenied("incomplete message")
        data.extend(chunk)
        if b"\n" in chunk:
            line, rest = bytes(data).split(b"\n", 1)
            if rest:
                raise GatewayDenied("one message per connection")
            return decode_message(line, limit=limit)
    raise GatewayDenied("message size limit")


def encode_message(value: dict, *, limit: int = MAX_RESPONSE) -> bytes:
    raw = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode()
    if len(raw) > limit:
        raise GatewayDenied("response size limit")
    return raw + b"\n"
