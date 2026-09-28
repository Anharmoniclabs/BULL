"""Regressions for the 2026-09-27/28 gateway reviews (delivery and display).

Earlier revisions of this file reproduced the defects; these tests now require
the fixed behavior. The gateway fixture uses real dispatch/permit logic but
replaces host certification and OS execution. Live IPC cases skip, never pass,
where Unix sockets are unavailable.
"""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
from types import SimpleNamespace

import pytest

from test_agent_gateway import call, config, gateway
from bulldog.agent_gateway import fit_result
from bulldog.agent_tool_registry import validate_gateway_config
from bulldog.gateway_transport import GatewayServer, _deliverable, request
from bulldog.gateway_wire import (
    CALL_DEADLINE,
    GatewayDenied,
    MAX_RESPONSE,
    MAX_TOOL_TIMEOUT,
    OUTPUT_FIELD_BYTES,
    RESULT_BYTES,
    json_size,
    decode_message,
    encode_message,
    safe_output,
)
from bulldog.mcp_gateway import MCP_FRAME_LIMIT, oversize_reply, validate_rpc

OUTPUTS = {
    "ascii": "a",
    "bmp": "é",
    "astral": "\U0001f600",
    "escape-heavy": '"\\',
    "controls": "\x1b\x07",
}


def hostile_output(gateway, text):
    original = gateway.authority.runtime.execute

    def execute(*args, **kwargs):
        return replace(original(*args, **kwargs), stdout=text, stderr=text)

    gateway.authority.runtime.execute = execute


def mcp_frame(result, request_id=2):
    import mcp.types as types

    response = types.JSONRPCResponse(
        jsonrpc="2.0",
        id=request_id,
        result=result.model_dump(by_alias=True, exclude_unset=True),
    )
    return (response.model_dump_json(by_alias=True, exclude_unset=True) + "\n").encode()


@pytest.mark.parametrize("kind", OUTPUTS)
@pytest.mark.parametrize("repeat", [7800, 8192, 100_000])
def test_completed_result_fits_authority_frame(gateway, kind, repeat):
    hostile_output(gateway, OUTPUTS[kind] * repeat)
    result = call(gateway)
    assert result["executed"] is True and result["status"] == "COMPLETED"
    oversized = json_size(OUTPUTS[kind] * repeat) > OUTPUT_FIELD_BYTES
    assert result["truncated"] is oversized
    raw = encode_message({"ok": True, "result": result})
    assert len(raw) <= RESULT_BYTES + 64
    assert gateway.authority.session.status()["uncertain_calls"] == 0


def test_small_output_is_not_marked_truncated(gateway):
    hostile_output(gateway, "\U0001f600 ok\n")
    result = call(gateway)
    assert result["stdout"] == "\U0001f600 ok\n"
    assert result["truncated"] is False and result["controls_replaced"] is False


@pytest.mark.parametrize("kind", OUTPUTS)
def test_completed_result_fits_mcp_frame(gateway, kind):
    pytest.importorskip("mcp")
    from test_mcp_gateway_sdk import invoke, server_for

    hostile_output(gateway, OUTPUTS[kind] * 100_000)
    result = invoke(
        server_for(gateway),
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        b'"params":{"name":"check","arguments":{}}}',
    )
    assert result.structured_content["executed"] is True
    assert len(mcp_frame(result)) < MCP_FRAME_LIMIT


def test_display_controls_are_neutralized_but_lines_kept(gateway):
    hostile_output(gateway, "\x1b]0;title\x07a\r\nb\rc‮d⁦e\tf")
    result = call(gateway)
    assert result["stdout"] == "�]0;title�a\nb�c�d�e\tf"
    assert result["controls_replaced"] is True and result["truncated"] is False


def test_safe_output_prefix_is_the_largest_that_fits():
    text, truncated, _ = safe_output("\U0001f600" * 1000, limit=122)
    assert truncated and len(text) == 10  # 2 quote bytes + 10 * 12 escaped bytes.


def test_oversize_result_keeps_the_true_outcome():
    result = {
        "call_id": "a" * 32,
        "content_trust": "untrusted tool output",
        "status": "COMPLETED",
        "executed": True,
        "returncode": 0,
        "stdout": "x" * RESULT_BYTES,
    }
    fitted = fit_result(result)
    assert fitted["executed"] is True and fitted["status"] == "COMPLETED"
    assert fitted["output_omitted"] is True and "stdout" not in fitted


def test_transport_delivers_outcome_when_result_cannot_encode():
    huge = {"call_id": "b" * 32, "status": "COMPLETED", "executed": True,
            "returncode": 0, "stdout": "\U0001f600" * MAX_RESPONSE}
    value = decode_message(_deliverable({"ok": True, "result": huge}), limit=MAX_RESPONSE)
    assert value["ok"] is True
    assert value["result"]["executed"] is True
    assert value["result"]["output_omitted"] is True


def test_mcp_oversize_reply_is_bounded_error_for_same_request():
    pytest.importorskip("mcp")
    import mcp.types as types

    reply = types.JSONRPCResponse(jsonrpc="2.0", id=7, result={"x": "y"})
    value = json.loads(oversize_reply(reply))
    assert value["id"] == 7 and value["error"]["code"] == -32603
    assert "audit" in value["error"]["message"]
    note = types.JSONRPCNotification(jsonrpc="2.0", method="notifications/x")
    with pytest.raises(GatewayDenied):
        oversize_reply(note)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"jsonrpc":"2.0","id":1,"result":{}}',
        b'{"jsonrpc":"2.0","id":"s","error":{"code":1,"message":"no"}}',
    ],
)
def test_client_replies_do_not_end_the_session(raw):
    assert "method" not in validate_rpc(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"jsonrpc":"2.0","result":{}}',
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}',
        b'{"jsonrpc":"2.0","id":1,"result":{},"params":{"argv":["sh"]}}',
        b'{"jsonrpc":"2.0","id":[1],"result":{}}',
    ],
)
def test_malformed_replies_still_rejected(raw):
    with pytest.raises(GatewayDenied):
        validate_rpc(raw)


def registry(**tool):
    value = config()
    value["tools"][0].update(tool)
    return value


@pytest.mark.parametrize(
    "field,text",
    [
        ("description", "Harmless check‮ ydaerla"),
        ("description", "zero​width"),
        ("description", "line break"),
        ("argv", ["/usr/bin/true", "--x⁦"]),
        ("argv", ["/usr/bin/true", ""]),
    ],
)
def test_registry_rejects_text_that_reads_differently(field, text):
    with pytest.raises(GatewayDenied):
        validate_gateway_config(registry(**{field: text}))


def test_registry_bounds_encoded_sizes():
    with pytest.raises(GatewayDenied):
        validate_gateway_config(registry(description="\U0001f600" * 100))
    with pytest.raises(GatewayDenied):
        validate_gateway_config(
            registry(argv=["/usr/bin/true", "\U0001f600" * 2000])
        )


def test_largest_valid_menu_fits_both_frames():
    # The whole signed registry is bounded by the request frame, so the menu is too.
    value = config()
    template = value["tools"][0]
    value["tools"] = [
        {**template, "name": f"tool{i:02d}", "description": "é" * 60}
        for i in range(32)
    ]
    validate_gateway_config(value)
    menu = {
        "tools": [
            {"name": x["name"], "description": x["description"],
             "inputSchema": {"type": "object", "properties": {},
                             "additionalProperties": False}}
            for x in value["tools"]
        ]
    }
    assert len(encode_message({"ok": True, "result": menu})) * 3 < MCP_FRAME_LIMIT


def network(url):
    value = config()
    value["tools"] = [{"name": "fetch", "description": "Fixed fetch",
                       "operation": "network.request", "url": url, "method": "GET"}]
    return value


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://10.0.0.5/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
        "https://[fd00::1]/",
        "https://localhost/",
        "https://metadata.google.internal/",
        "https://printer.local/",
        "https://intranet/",
        "https://0.0.0.0/",
    ],
)
def test_fixed_urls_cannot_target_local_or_private_hosts(url):
    with pytest.raises(GatewayDenied, match="public host"):
        validate_gateway_config(network(url))


def test_fixed_public_url_still_accepted():
    validate_gateway_config(network("https://example.com/manual"))
    validate_gateway_config(network("https://93.184.215.14/"))


def test_client_deadline_exceeds_longest_signed_tool():
    assert CALL_DEADLINE > MAX_TOOL_TIMEOUT
    with pytest.raises(GatewayDenied):
        validate_gateway_config(registry(timeout=MAX_TOOL_TIMEOUT + 1))


def live_server(tmp_path, handle):
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()
    except OSError as exc:
        pytest.skip(f"live Unix IPC unavailable: {exc}; not a transport PASS")
    directory = tmp_path / "endpoint"
    directory.mkdir(mode=0o700)
    authority = SimpleNamespace(config={"agent_uid": os.geteuid()}, handle=handle)
    path = directory / "agent.sock"
    return GatewayServer(authority, path, agent_gid=os.getegid()), path


def test_request_abandoned_while_queued_never_runs(tmp_path):
    calls = []
    server, path = live_server(tmp_path, lambda m, **k: calls.append(m) or {})
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(path))  # Queued in the backlog; no one is accepting yet.
    client.sendall(encode_message({"method": "call"}))
    client.close()  # The client gave up before the authority reached it.
    thread = threading.Thread(target=server.serve)
    thread.start()
    try:
        live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        live.settimeout(5)
        live.connect(str(path))
        live.sendall(encode_message({"method": "list"}))
        assert json.loads(live.makefile("rb").readline())["ok"] is True
        live.close()
        assert calls == [{"method": "list"}]
    finally:
        server.close()
        thread.join(timeout=3)


def test_live_transport_delivers_outcome_of_huge_result(tmp_path, monkeypatch):
    huge = {"call_id": "c" * 32, "status": "COMPLETED", "executed": True,
            "returncode": 0, "stdout": "\U0001f600" * MAX_RESPONSE}
    server, path = live_server(tmp_path, lambda m, **k: huge)
    thread = threading.Thread(target=server.serve)
    thread.start()
    try:
        if os.geteuid() == 0:
            pytest.skip("client refuses a root authority UID; covered by unit test")
        value = request(path, server_uid=os.geteuid(), message={"method": "list"})
        assert value["result"]["executed"] is True
        assert value["result"]["output_omitted"] is True
    finally:
        server.close()
        thread.join(timeout=3)
