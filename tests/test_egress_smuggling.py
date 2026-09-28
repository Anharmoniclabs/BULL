"""Red-team regressions: one inspected HTTP request per gateway connection.

A live origin records exactly what the gateway forwards. Upstreams are local
test servers reached through an explicit resolver; nothing leaves the host.
"""

import asyncio
import socket

import pytest

from bulldog.egress_gateway import (
    EgressGateway,
    EgressPolicy,
    EgressRequest,
    GatewayConfig,
    _DnsProtocol,
    parse_http_head,
    public_resolver,
)

HOST = "api.example.com"
POLICY = {HOST: {"methods": ["GET", "POST"], "paths": ["/v1"]}}


async def exchange(payload: bytes, *, pause_then: bytes = b"", injector=None):
    """Send payload through a gateway to a recording origin; return both views."""
    received = []

    async def origin(reader, writer):
        data = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), 0.5)
                if not chunk:
                    break
                data += chunk
        except asyncio.TimeoutError:
            pass
        received.append(data)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    port = origin_server.sockets[0].getsockname()[1]
    gateway = EgressGateway(
        EgressPolicy(POLICY),
        GatewayConfig(resolver=lambda host: ("127.0.0.1", port)),
        header_injector=injector,
    )
    gateway_server = await asyncio.start_server(gateway._handle_stream, "127.0.0.1", 0)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", gateway_server.sockets[0].getsockname()[1]
    )
    writer.write(payload)
    await writer.drain()
    if pause_then:
        await asyncio.sleep(0.1)
        try:
            writer.write(pause_then)
            await writer.drain()
        except ConnectionError:
            pass
    try:
        response = await asyncio.wait_for(reader.read(), 3)
    except (ConnectionError, asyncio.TimeoutError):
        response = b""
    writer.close()
    gateway_server.close()
    origin_server.close()
    return b"".join(received), response


def run(coro):
    return asyncio.run(coro)


def test_pipelined_second_request_is_refused():
    first = f"GET /v1/ok HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
    second = f"DELETE /admin HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
    forwarded, response = run(exchange(first + second))
    assert forwarded == b"" and b"200" not in response


def test_keepalive_second_request_never_reaches_upstream():
    first = f"GET /v1/ok HTTP/1.1\r\nHost: {HOST}\r\nConnection: keep-alive\r\n\r\n".encode()
    second = f"GET /admin HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
    forwarded, _ = run(exchange(first, pause_then=second))
    assert forwarded.count(b"HTTP/1.1\r\n") == 1
    assert b"/admin" not in forwarded
    assert b"Connection: close\r\n" in forwarded
    assert b"keep-alive" not in forwarded.lower()


def test_body_beyond_content_length_is_not_forwarded():
    body = b'{"a":1}'
    request = (
        f"POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode()
    smuggled = f"GET /admin HTTP/1.1\r\nHost: {HOST}\r\n\r\n".encode()
    forwarded, response = run(exchange(request, pause_then=body + smuggled))
    assert forwarded.endswith(body) and b"/admin" not in forwarded
    assert b"200" in response


def test_chunked_body_is_refused():
    request = (
        f"POST /v1/items HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
    ).encode()
    forwarded, _ = run(exchange(request))
    assert forwarded == b""


@pytest.mark.parametrize(
    "head",
    [
        b"GET /v1/ok HTTP/1.1\r\nHost: api.example.com\r\nX-A: 1\nAuthorization: Bearer x\r\n\r\n",
        b"GET /v1/ok HTTP/1.1\r\nHost: api.example.com\nHost: evil.example\r\n\r\n",
        b"GET /v1/ok HTTP/1.1\r\nHost: api.example.com\r\nX-A: 1\rX-B: 2\r\n\r\n",
        b"GET /v1/ok HTTP/1.1\r\nHost: api.example.com\x00\r\n\r\n",
        b"GET /v1/ok HTTP/2.0\r\nHost: api.example.com\r\n\r\n",
    ],
)
def test_ambiguous_header_framing_is_refused(head):
    assert parse_http_head(head) is None
    forwarded, _ = run(exchange(head))
    assert forwarded == b""


def test_client_copies_of_injected_headers_are_removed():
    request = (
        f"GET /v1/ok HTTP/1.1\r\nHost: {HOST}\r\nX-Api-Key: agent-chosen\r\n"
        "Authorization: Bearer agent\r\nUpgrade: websocket\r\n\r\n"
    ).encode()
    forwarded, _ = run(exchange(request, injector=lambda req: {"X-Api-Key": "broker"}))
    assert b"agent-chosen" not in forwarded and b"X-Api-Key: broker" in forwarded
    assert b"Bearer agent" not in forwarded and b"websocket" not in forwarded


@pytest.mark.parametrize(
    "path",
    ["/v1/../admin", "/v1/%2e%2e/admin", "/v1/%2E%2e/admin", "/v1%2fadmin",
     "/v1/..%2fadmin", "/v1\\..\\admin", "/v1-admin", "/v10"],
)
def test_path_rules_cannot_be_escaped(path):
    allowed, _ = EgressPolicy(POLICY).decide(
        EgressRequest("http_request", HOST, "GET", path)
    )
    assert allowed is False


@pytest.mark.parametrize("path", ["/v1", "/v1/items", "/v1?q=1", "/v1/a.b/c"])
def test_path_rules_still_allow_the_subtree(path):
    assert EgressPolicy(POLICY).decide(
        EgressRequest("http_request", HOST, "GET", path)
    )[0] is True


def dns_query(labels):
    question = b"".join(bytes([len(x)]) + x for x in labels) + b"\x00\x00\x01\x00\x01"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question


def test_dotted_single_dns_label_does_not_match_allowlist():
    assert _DnsProtocol._decode_qname(dns_query([b"api.example.com"])) is None
    assert _DnsProtocol._decode_qname(dns_query([b"api", b"example", b"com"])) == HOST


@pytest.mark.parametrize(
    "answer", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::5", "192.168.0.1"]
)
def test_resolver_refuses_rebinding_to_internal_addresses(monkeypatch, answer):
    family = socket.AF_INET6 if ":" in answer else socket.AF_INET
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [(family, socket.SOCK_STREAM, 6, "", (answer, 0))],
    )
    with pytest.raises(OSError, match="no public address"):
        public_resolver(HOST)


def test_resolver_returns_public_answer_with_protocol_default_port(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0)),
        ],
    )
    assert public_resolver(HOST) == ("93.184.215.14", None)
