"""Validate host-signed, fixed tools. Agent input can select a name, never argv.

This first catalog deliberately has no free-form shell, secret-returning tool,
plugin loading, dynamic URL, upload, or administrator operation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from urllib.parse import urlsplit

from .gateway_wire import GatewayDenied, MAX_TOOL_TIMEOUT, decode_message, json_size
from .models import Capability
from .public_address import is_public

_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_INPUT = {"type": "object", "properties": {}, "additionalProperties": False}


# Controls, format (bidirectional, zero-width), surrogate, private-use,
# unassigned and line/paragraph separators can make a signed command or
# description read differently to its human reviewer than it executes.
_HIDDEN = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _text(value, maximum, *, encoded=None):
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and not any(unicodedata.category(c) in _HIDDEN for c in value)
        and (encoded is None or json_size(value) <= encoded)
    )


def _public_host(host: str) -> bool:
    """Fixed URLs name public services; internal targets need another adapter."""
    host = host.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(
        (".localhost", ".local", ".internal", ".home.arpa")
    ):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "." in host and "%" not in host  # Single-label names are local.
    return is_public(address)


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
        if not _text(tool.get("description"), 512, encoded=1024):
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
                or json_size(argv) > 16384
                or not argv[0].startswith("/")
            ):
                raise GatewayDenied("invalid fixed command")
            if not isinstance(tool["executable_sha256"], str) or not _HASH.fullmatch(
                tool["executable_sha256"]
            ):
                raise GatewayDenied("executable digest is required")
            if (
                type(tool["timeout"]) is not int
                or not 1 <= tool["timeout"] <= MAX_TOOL_TIMEOUT
            ):
                raise GatewayDenied(
                    f"tool timeout must be 1..{MAX_TOOL_TIMEOUT} seconds"
                )
        elif tool.get("operation") == "network.request":
            if set(tool) != common | {"url", "method"} or tool["method"] not in (
                "GET",
                "HEAD",
            ):
                raise GatewayDenied("network tool requires a fixed GET/HEAD URL")
            if not _text(tool["url"], 4096, encoded=4096):
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
            if not _public_host(url.hostname):
                raise GatewayDenied(
                    "fixed URL must name a public host, not a loopback, "
                    "private, link-local or local-only address"
                )
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
