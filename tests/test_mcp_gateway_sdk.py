"""SDK handler integration with real production routing, without a fake PASS
for the OS transport. The synchronous authority fixture contains no awaitable IO;
its async SDK handlers can therefore be evaluated without an event loop here.
"""

import json

import pytest

from test_agent_gateway import gateway
from bulldog.mcp_gateway import build_server, validate_rpc

mcp = pytest.importorskip(
    "mcp", reason="install BULL's pinned mcp extra to test SDK integration"
)


def invoke(server, raw):
    message = validate_rpc(raw)
    entry = server.get_request_handler(message["method"])
    params = entry.params_type.model_validate(message.get("params", {}))
    coro = entry.handler(None, params)
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    finally:
        coro.close()
    raise AssertionError("fixture unexpectedly needs asynchronous transport")


def server_for(g):
    async def forward(message):
        return g.authority.handle(message, peer_uid=g.config["agent_uid"])

    return build_server(forward)


def test_sdk_list_and_call_reach_production_command(gateway):
    server = server_for(gateway)
    menu = invoke(server, b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
    assert [x.name for x in menu.tools] == ["check"]
    result = invoke(
        server,
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check","arguments":{}}}',
    )
    assert result.is_error is False
    assert result.structured_content["executed"] is True
    assert gateway.effects == [tuple(gateway.config["tools"][0]["argv"])]


def test_sdk_unknown_tool_yields_bounded_error_with_no_effect(gateway):
    server = server_for(gateway)
    result = invoke(
        server,
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{}}}',
    )
    assert result.is_error is True
    assert gateway.effects == []
    assert len(result.content[0].text) < 256


def test_sdk_never_advertises_admin_resources_or_sampling(gateway):
    server = server_for(gateway)
    capabilities = server.create_initialization_options().capabilities
    assert capabilities.tools is not None
    assert (
        capabilities.resources is None
        and capabilities.prompts is None
        and capabilities.tasks is None
    )
    assert server.get_request_handler("admin.approve") is None
    assert server.middleware == []
