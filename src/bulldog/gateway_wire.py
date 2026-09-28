"""Bounded, unambiguous messages for the local agent connector."""

from __future__ import annotations

import json
import socket
import time

MAX_REQUEST = 32 * 1024
MAX_RESPONSE = 192 * 1024
# Limits are on encoded bytes, never characters: \uXXXX escaping of astral text
# is 12 bytes per character, and MCP carries a text copy of the structured result.
OUTPUT_FIELD_BYTES = 8192  # Per output stream, measured as ensure_ascii JSON.
RESULT_BYTES = 48 * 1024  # Whole authority result; MCP stays below ~3x this.
MAX_TOOL_TIMEOUT = 120
# Covers trusted-state checks, admission scanning, sandbox setup and audit.
AUTHORITY_OVERHEAD = 60
CALL_DEADLINE = MAX_TOOL_TIMEOUT + AUTHORITY_OVERHEAD

# Terminal and bidirectional controls in untrusted output can rewrite what a
# human sees in a client UI. \n and \t are kept; CRLF becomes LF.
_UNSAFE_OUTPUT = {
    **{c: 0xFFFD for c in range(0x20) if c not in (0x09, 0x0A)},
    **{c: 0xFFFD for c in range(0x7F, 0xA0)},
    **{c: 0xFFFD for c in (0x061C, 0x200E, 0x200F)},
    **{c: 0xFFFD for c in range(0x202A, 0x202F)},
    **{c: 0xFFFD for c in range(0x2066, 0x206A)},
}


class GatewayDenied(ValueError):
    pass


def json_size(value) -> int:
    return len(
        json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    )


def safe_output(text: str, limit: int = OUTPUT_FIELD_BYTES) -> tuple[str, bool, bool]:
    """Neutralize display controls, then cut to fit ``limit`` escaped bytes.

    Returns ``(text, truncated, controls_replaced)``.
    """
    # Each character escapes to at least one byte (CRLF to one), so a longer
    # prefix can never fit; this bounds the work spent on hostile output.
    head = text[: 2 * limit]
    truncated = len(head) < len(text)
    unified = head.replace("\r\n", "\n")
    clean = unified.translate(_UNSAFE_OUTPUT)
    replaced = clean != unified
    if json_size(clean) <= limit:
        return clean, truncated, replaced
    low, high = 0, len(clean)
    while low < high:  # Largest prefix whose escaped form fits.
        middle = (low + high + 1) // 2
        if json_size(clean[:middle]) <= limit:
            low = middle
        else:
            high = middle - 1
    return clean[:low], True, replaced


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
