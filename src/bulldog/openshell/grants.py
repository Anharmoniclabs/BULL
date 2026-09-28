"""Signed per-sandbox grants for OpenShell sandboxes.

Carried in the ``openshell`` section of a signed BULL policy bundle, so the
same HMAC that protects the capability ceiling protects these grants.

    {
      "format": "bull-openshell-grants-v1",
      "host_ceiling": ["api.github.com", "httpbin.org"],
      "sandboxes": {
        "coder-1": {
          "capabilities": ["network.outbound", "network.post"],
          "trusted_sources": ["api.github.com"]
        }
      }
    }

``host_ceiling`` bounds every OpenShell network policy BULL will accept, at
creation or on any later change. ``trusted_sources`` are hosts whose content
does not taint a sandbox's provenance; content from any other host does.
Sandboxes without an entry receive no capabilities.
"""

from __future__ import annotations

import re

from ..models import Capability

_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}\Z")
_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9*]([a-z0-9.*-]*[a-z0-9])?\Z")


class GrantError(ValueError):
    pass


def _hosts(value, label, *, ports=False):
    def valid(entry):
        if not isinstance(entry, str):
            return False
        host, sep, port = entry.lower().partition(":")
        if sep and not (ports and port.isdigit() and 0 < int(port) < 65536):
            return False
        return bool(_HOST.fullmatch(host))

    if not isinstance(value, list) or not all(valid(h) for h in value):
        suffix = " (optionally host:port)" if ports else ""
        raise GrantError(f"{label} must be a list of lowercase host patterns{suffix}")
    return sorted({h.lower() for h in value})


def validate_grants(value: dict) -> dict:
    if not isinstance(value, dict) or value.get("format") != "bull-openshell-grants-v1":
        raise GrantError("unsupported OpenShell grants format")
    if set(value) - {"format", "host_ceiling", "sandboxes"}:
        raise GrantError("unknown OpenShell grants field")
    sandboxes = value.get("sandboxes")
    if not isinstance(sandboxes, dict):
        raise GrantError("sandboxes must be an object")
    clean = {}
    for name, grant in sandboxes.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise GrantError(f"invalid sandbox name {name!r}")
        if not isinstance(grant, dict) or set(grant) - {"capabilities", "trusted_sources"}:
            raise GrantError(f"invalid grant for {name}")
        try:
            caps = sorted({Capability(c).value for c in grant.get("capabilities", [])})
        except ValueError as exc:
            raise GrantError(f"unknown capability for {name}") from exc
        clean[name] = {
            "capabilities": caps,
            "trusted_sources": _hosts(grant.get("trusted_sources", []), "trusted_sources",
                                      ports=True),
        }
    return {
        "format": "bull-openshell-grants-v1",
        "host_ceiling": _hosts(value.get("host_ceiling", []), "host_ceiling"),
        "sandboxes": clean,
    }


def host_matches(host: str, pattern: str) -> bool:
    """OpenShell-style host patterns: exact, or ``*.`` for one or more labels."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and len(host) > len(pattern) - 1
    return host == pattern
