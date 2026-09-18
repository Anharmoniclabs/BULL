"""Thin browser adapter around BULL's real canonicalizer/policy/session guard.

The GitHub Pages workflow copies the exact source files from src/bulldog into the
same generated package before deployment. This adapter contains no policy rules.
"""
from __future__ import annotations

import json

from .canonicalizer import (
    ActionCanonicalizationError,
    TrustedExecutionContext,
    canonicalize_action,
)
from .models import Capability, Provenance
from .policy import DeterministicPolicy
from .session_guard import SessionGuard


_POLICY = DeterministicPolicy()
_GUARD = SessionGuard()


def _capabilities(values) -> frozenset[Capability]:
    return frozenset(Capability(str(value)) for value in (values or []))


def _provenance(values) -> tuple[Provenance, ...]:
    if values is None:
        return (Provenance.UNKNOWN,)
    if isinstance(values, str):
        values = [values]
    return tuple(Provenance(str(value)) for value in values)


def _security_context(session_id: str) -> str:
    return "browser-lab:" + str(session_id or "default")


def _guard_key(session_id: str) -> str:
    return "security-context:" + _security_context(session_id)


def reset_session(session_id: str = "default") -> dict:
    _GUARD.clear(_guard_key(session_id))
    return {"status": "ok", "session_id": str(session_id or "default")}


def reset_session_json(session_id: str = "default") -> str:
    return json.dumps(reset_session(session_id), sort_keys=True)


def evaluate(payload: dict) -> dict:
    session_id = str(payload.get("session_id") or payload.get("actor") or "default")

    trusted = TrustedExecutionContext(
        actor=str(payload.get("actor") or "browser-agent"),
        provenance=_provenance(payload.get("provenance")),
        security_context_id=_security_context(session_id),
        domain_id="browser-domain:" + session_id,
        root_domain_id="browser-root:" + session_id,
        model_id=str(payload.get("model_id") or "browser-user-supplied"),
        spawn_depth=int(payload.get("spawn_depth") or 0),
    )

    parent_raw = payload.get("parent_capabilities")
    parent_capabilities = None if parent_raw is None else _capabilities(parent_raw)

    proposal = {
        "task": str(payload.get("task") or "browser policy evaluation"),
        "operation": str(payload.get("operation") or ""),
        "resource": str(payload.get("resource") or ""),
    }

    try:
        action = canonicalize_action(
            proposal,
            trusted=trusted,
            granted_capabilities=_capabilities(payload.get("granted_capabilities")),
            parent_capabilities=parent_capabilities,
        )
    except ActionCanonicalizationError as exc:
        return {
            "status": "rejected",
            "stage": "canonicalizer",
            "decision": "REJECT",
            "error_type": type(exc).__name__,
            "reasons": [str(exc)],
            "session_id": session_id,
            "executed_modules": [
                "src/bulldog/models.py",
                "src/bulldog/canonicalizer.py",
            ],
        }

    policy_result = _POLICY.evaluate(action)
    result = _GUARD.enforce(action, policy_result)

    return {
        "status": "evaluated",
        "stage": "policy+session_guard",
        "decision": result.decision.value,
        "risk": result.risk,
        "hard_block": result.hard_block,
        "reasons": list(result.reasons),
        "session_id": session_id,
        "action": {
            "actor": action.actor,
            "operation": action.operation,
            "resource": action.resource,
            "derived_capability": action.capability.value,
            "granted_capabilities": sorted(
                capability.value for capability in action.granted_capabilities
            ),
            "parent_capabilities": (
                None
                if action.parent_capabilities is None
                else sorted(
                    capability.value for capability in action.parent_capabilities
                )
            ),
            "provenance": [item.value for item in action.provenance],
        },
        "executed_modules": [
            "src/bulldog/models.py",
            "src/bulldog/canonicalizer.py",
            "src/bulldog/policy.py",
            "src/bulldog/session_guard.py",
        ],
    }


def evaluate_json(raw: str) -> str:
    try:
        payload = json.loads(str(raw))
        if not isinstance(payload, dict):
            raise TypeError("request must be a JSON object")
        return json.dumps(evaluate(payload), sort_keys=True)
    except (KeyError, TypeError, ValueError) as exc:
        return json.dumps(
            {
                "status": "error",
                "stage": "input",
                "error_type": type(exc).__name__,
                "reasons": [str(exc)],
            },
            sort_keys=True,
        )


def self_test() -> dict:
    cases = [
        (
            "safe_project_read",
            {
                "actor": "selftest-safe",
                "session_id": "selftest-safe",
                "operation": "read",
                "resource": "/workspace/README.md",
                "provenance": ["local_trusted"],
                "granted_capabilities": ["fs.read.project"],
            },
            "ALLOW",
        ),
        (
            "external_credential_access",
            {
                "actor": "selftest-credential",
                "session_id": "selftest-credential",
                "operation": "credential.read",
                "resource": "service-token",
                "provenance": ["internet"],
                "granted_capabilities": ["credential.read"],
            },
            "DENY",
        ),
        (
            "encoded_traversal",
            {
                "actor": "selftest-traversal",
                "session_id": "selftest-traversal",
                "operation": "read",
                "resource": "/workspace/%2e%2e/etc/shadow",
                "provenance": ["local_trusted"],
                "granted_capabilities": ["fs.read.project"],
            },
            "REJECT",
        ),
        (
            "child_authority_escalation",
            {
                "actor": "selftest-child",
                "session_id": "selftest-child",
                "operation": "credential.read",
                "resource": "service-token",
                "provenance": ["local_trusted"],
                "granted_capabilities": ["credential.read"],
                "parent_capabilities": ["process.exec"],
            },
            "DENY",
        ),
        (
            "external_process_exec",
            {
                "actor": "selftest-exec",
                "session_id": "selftest-exec",
                "operation": "exec",
                "resource": "/usr/bin/curl",
                "provenance": ["internet"],
                "granted_capabilities": ["process.exec"],
            },
            "ESCALATE",
        ),
        (
            "canary_access",
            {
                "actor": "selftest-canary",
                "session_id": "selftest-canary",
                "operation": "read",
                "resource": "/workspace/.bulldog-canary",
                "provenance": ["local_trusted"],
                "granted_capabilities": ["fs.read.project"],
            },
            "DENY",
        ),
    ]

    results = []
    for name, request, expected in cases:
        reset_session(request["session_id"])
        output = evaluate(request)
        actual = output.get("decision")
        results.append(
            {
                "name": name,
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
            }
        )

    return {
        "passed": all(item["passed"] for item in results),
        "cases": results,
        "source": "real BULL canonicalizer + policy + session guard",
    }


def self_test_json() -> str:
    return json.dumps(self_test(), sort_keys=True)
