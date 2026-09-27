"""Real serialized SDK/stdio transport; the authority is a labelled fixture.

The actual production effect and kernel peer boundaries are tested separately.
No result here qualifies a deployment or a native coding client.
"""

import asyncio
import os
from pathlib import Path
import socket
import sys

import pytest

pytest.importorskip("mcp")


def test_actual_sdk_stdio_handshake_and_tool_exchange():
    # asyncio requires a local socketpair for its event-loop wakeup channel.
    try:
        a, b = socket.socketpair()
        a.close()
        b.close()
    except OSError as exc:
        pytest.skip(f"stdio SDK event loop unavailable: {exc}; not a live MCP PASS")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    source = str(Path(__file__).resolve().parents[1] / "src")
    script = """
import asyncio, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import bulldog.mcp_gateway as bridge
def authority(socket_path, *, server_uid, message):
    if message['method'] == 'list':
        return {'ok': True, 'result': {'tools': [{'name': 'fixture', 'description': 'transport fixture', 'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}}]}}
    return {'ok': True, 'result': {'status': 'COMPLETED', 'executed': False, 'fixture': 'transport only'}}
bridge.request = authority
asyncio.run(bridge.serve(Path('/unused-fixture'), 12345))
"""

    async def exchange():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-c", script, source],
            env={"PATH": os.defpath},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=10) as session:
                initialized = await session.initialize()
                assert initialized.server_info.name == "bull"
                menu = await session.list_tools()
                assert [x.name for x in menu.tools] == ["fixture"]
                result = await session.call_tool("fixture", {})
                assert result.structured_content["fixture"] == "transport only"
                assert result.structured_content["executed"] is False

    asyncio.run(exchange())
