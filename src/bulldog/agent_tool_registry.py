"""Validate host-signed, fixed tools. Agent input can select a name, never argv.

This first catalog deliberately has no free-form shell, secret-returning tool,
plugin loading, dynamic URL, upload, or administrator operation.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .gateway_wire import GatewayDenied, decode_message
from .models import Capability

_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_INPUT = {"type": "object", "properties": {}, "additionalProperties": False}


def _text(value, maximum):
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def validate_gateway_config(value: dict) -> dict:
    # Copies and bounds the whole signed configuration before examining fields.
    try:
        value = decode_message(json.dumps(value, allow_nan=False).encode())
    except (TypeError, ValueError) as exc:
        raise GatewayDenied("invalid gateway configuration") from exc
    required = {
        "format",
        "tenant_id",
        "project_id",
        "session_id",
        "agent_uid",
        "expires_at",
        "max_calls",
        "tools",
    }
    if set(value) != required or value["format"] != "bull-agent-gateway-v1":
        raise GatewayDenied("unsupported gateway configuration")
    for field in ("tenant_id", "project_id", "session_id"):
        if not isinstance(value[field], str) or not _ID.fullmatch(value[field]):
            raise GatewayDenied("invalid gateway identity")
    if type(value["agent_uid"]) is not int or not 0 < value["agent_uid"] < 2**31:
        raise GatewayDenied("agent UID must be a non-root OS identity")
    if type(value["expires_at"]) is not int or value["expires_at"] <= 0:
        raise GatewayDenied("absolute lease expiry is required")
    if type(value["max_calls"]) is not int or not 1 <= value["max_calls"] <= 10000:
        raise GatewayDenied("max_calls must be 1..10000")
    tools = value["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 32:
        raise GatewayDenied("catalog must contain 1..32 fixed tools")
    names = set()
    for tool in tools:
        if not isinstance(tool, dict):
            raise GatewayDenied("invalid tool")
        name = tool.get("name")
        if not isinstance(name, str) or not _ID.fullmatch(name) or name in names:
            raise GatewayDenied("invalid or repeated tool name")
        names.add(name)
        if not _text(tool.get("description"), 512):
            raise GatewayDenied("invalid tool description")
        common = {"name", "description", "operation"}
        if tool.get("operation") == "process.execute":
            if set(tool) != common | {"argv", "executable_sha256", "timeout"}:
                raise GatewayDenied(
                    "process tool requires fixed argv, digest and timeout"
                )
            argv = tool["argv"]
            if (
                not isinstance(argv, list)
                or not 1 <= len(argv) <= 64
                or any(not _text(x, 4096) for x in argv)
                or sum(len(x) for x in argv) > 8192
                or not argv[0].startswith("/")
            ):
                raise GatewayDenied("invalid fixed command")
            if not isinstance(tool["executable_sha256"], str) or not _HASH.fullmatch(
                tool["executable_sha256"]
            ):
                raise GatewayDenied("executable digest is required")
            if type(tool["timeout"]) is not int or not 1 <= tool["timeout"] <= 120:
                raise GatewayDenied("tool timeout must be 1..120 seconds")
        elif tool.get("operation") == "network.request":
            if set(tool) != common | {"url", "method"} or tool["method"] not in (
                "GET",
                "HEAD",
            ):
                raise GatewayDenied("network tool requires a fixed GET/HEAD URL")
            if not _text(tool["url"], 4096):
                raise GatewayDenied("invalid fixed URL")
            try:
                url = urlsplit(tool["url"])
                if (
                    url.scheme != "https"
                    or not url.hostname
                    or url.username
                    or url.password
                    or url.fragment
                    or url.port not in (None, 443)
                ):
                    raise ValueError("unsupported URL")
            except ValueError as exc:
                raise GatewayDenied(
                    "fixed URL must be HTTPS on port 443 without credentials or fragment"
                ) from exc
        else:
            raise GatewayDenied("tool has no supported adapter")
    return value


def capability_for(tool: dict) -> Capability:
    return (
        Capability.PROCESS_EXEC
        if tool["operation"] == "process.execute"
        else Capability.NETWORK_OUTBOUND
    )


def available_tools(config: dict, ceiling: frozenset[Capability]) -> dict:
    return {
        tool["name"]: tool
        for tool in config["tools"]
        if capability_for(tool) in ceiling
    }
