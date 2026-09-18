"""Pure deterministic policy model used by BULL's browser Playground.

The module is deliberately dependency-free so it can execute under Pyodide.
It is not a host sandbox and must never be presented as a Linux attestation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _trace(kind: str, stage: str, detail: str) -> dict[str, str]:
    return {"kind": kind, "stage": stage, "detail": detail}


def evaluate_request(request: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a structured request using browser-safe deterministic rules."""
    request = dict(request or {})
    trace: list[dict[str, str]] = []
    agent = str(request.get("agent", "unknown"))
    parent = str(request.get("parent", "root"))
    action = str(request.get("action", ""))
    target = str(request.get("target", request.get("resource", "")))
    caps = {str(x) for x in request.get("capabilities", [])}
    parent_caps = {str(x) for x in request.get("parentCapabilities", request.get("capabilities", []))}

    trace.append(_trace("pass", "identity", f"agent={agent}; parent={parent}"))

    claimed = str(request.get("provenance", "unknown"))
    canonical = str(request.get("canonicalProvenance", claimed))
    if claimed != canonical:
        trace.append(_trace("fail", "provenance", f"claimed={claimed}; canonical={canonical}"))
        return _result("DENY", "The supplied provenance does not match the canonical source identity.", request, trace)
    trace.append(_trace("pass", "provenance", canonical))

    if not action or action not in caps:
        trace.append(_trace("fail", "capability", f"{action or 'missing action'} is absent from agent capabilities"))
        return _result("DENY", "The agent lacks the requested capability.", request, trace)
    trace.append(_trace("pass", "capability", f"{action} is present"))

    if action not in parent_caps:
        trace.append(_trace("fail", "parent_authority", f"{action} is not inherited from {parent}"))
        return _result("DENY", "A child security domain cannot acquire authority absent from its parent ceiling.", request, trace)
    trace.append(_trace("pass", "parent_authority", "requested authority is inherited"))

    if action == "secrets.read" and request.get("secretGrant") is not True:
        trace.append(_trace("fail", "secret_broker", "missing authenticated, domain-bound grant"))
        return _result("DENY", "Secret access requires a separate authenticated broker grant.", request, trace)

    if action in {"filesystem.read", "filesystem.write"}:
        roots = [str(x) for x in request.get("allowedRoots", ["/workspace"])]
        if ".." in target or not any(target == root or target.startswith(root + "/") for root in roots):
            trace.append(_trace("fail", "resource_binding", f"{target} is outside allowed roots"))
            return _result("DENY", "The requested path is not bound to an approved resource root.", request, trace)
        trace.append(_trace("pass", "resource_binding", target))

    if action == "process.exec" and target.startswith(("http://", "https://")):
        host = target.split("/", 3)[2]
        allowlist = {str(x) for x in request.get("egressAllowlist", [])}
        if host not in allowlist:
            trace.append(_trace("fail", "egress", f"{host} is absent from the egress ceiling"))
            return _result("DENY", "Execution authority does not authorize arbitrary external communication.", request, trace)
        trace.append(_trace("pass", "egress", f"{host} is allowlisted"))

    if request.get("goal") and request.get("proposedGoal") and request["goal"] != request["proposedGoal"]:
        trace.append(_trace("warn", "goal_transition", "behavior exceeds declared intent"))
        return _result("SANDBOX", "Goal drift requires a stronger isolated execution boundary.", request, trace)

    if action == "agent.spawn":
        trace.append(_trace("warn", "delegation", "child domain needs an explicit authority review"))
        return _result("REVIEW", "Agent spawning requires an explicit child-domain authorization review.", request, trace)

    trace.append(_trace("pass", "decision", "all deterministic policy checks passed"))
    return _result("ALLOW", "The request satisfies the browser policy model.", request, trace)


def _result(decision: str, reason: str, request: dict[str, Any], trace: list[dict[str, str]]) -> dict[str, Any]:
    event = {
        "format": "bull-browser-audit-v1",
        "mode": "local-pyodide-policy-model",
        "decision": decision,
        "reason": reason,
        "request": request,
        "trace": trace,
    }
    event["audit_hash"] = hashlib.sha256(_canonical(event).encode("utf-8")).hexdigest()
    return event


def evaluate_json(raw: str) -> str:
    """Evaluate JSON text and return canonical JSON suitable for JS callers."""
    try:
        request = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        return _canonical({"format": "bull-browser-audit-v1", "decision": "DENY", "reason": f"Invalid request JSON: {exc}", "trace": []})
    if not isinstance(request, dict):
        return _canonical({"format": "bull-browser-audit-v1", "decision": "DENY", "reason": "Request must be a JSON object.", "trace": []})
    return _canonical(evaluate_request(request))
