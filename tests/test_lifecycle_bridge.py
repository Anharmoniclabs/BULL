"""A real lifecycle admission reaches only the host-bound production adapter."""

from pathlib import Path
from types import SimpleNamespace
import secrets

import pytest

from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import DispatchRequest
from bulldog.lifecycle_bridge import GovernedProductionExecution
from bulldog.lifecycle_governance import Effect, LifecycleGovernor, Rejected
from bulldog.models import Capability, Decision, Provenance
from bulldog.profiles import ProductionDispatcher


def test_exact_one_use_lifecycle_then_production_dispatch(tmp_path):
    key, host, calls = secrets.token_bytes(32), object(), []
    governor = LifecycleGovernor(tmp_path / "state.db", key, host_key=host)
    root = governor.create_domain(
        {governor.scope(Effect.EXECUTE, "tool")}, host_key=host
    )
    governor.observe(root, "host task", trusted=True, host_key=host)
    command = ("/usr/bin/true", "--version")
    request = DispatchRequest(
        proposal={
            "capability": "process.exec",
            "operation": "execute",
            "resource": command[0],
        },
        trusted=TrustedExecutionContext("host", (Provenance.HUMAN,), "host"),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        authorized_command=command,
    )
    dispatcher = object.__new__(ProductionDispatcher)
    dispatcher.execute = lambda *args, **kwargs: (
        calls.append((args, kwargs))
        or SimpleNamespace(
            executed=True,
            evaluation=SimpleNamespace(decision=Decision.ALLOW),
            returncode=0,
        )
    )
    bridge = GovernedProductionExecution(
        governor=governor,
        host_key=host,
        dispatcher=dispatcher,
        actor=root,
        target="tool",
        dispatch_request=request,
        command=command,
        project_root=tmp_path,
    )
    effect = bridge.request()
    assert bridge.submit(effect, "forged token").decision == "DENY"
    assert calls == []
    token = governor.mint(effect, host_key=host)
    result = bridge.submit(effect, token)
    assert result.decision == "ALLOW" and result.output == {
        "executed": True,
        "decision": "ALLOW",
        "returncode": 0,
    }
    assert calls[0][0] == (request, command)
    assert calls[0][1]["project_root"] == tmp_path
    assert bridge.submit(effect, token).decision == "DENY"
    assert len(calls) == 1
    assert governor.verify()["valid"] is True
    governor.close()


def test_changed_command_or_effect_never_reaches_dispatcher(tmp_path):
    key, host = secrets.token_bytes(32), object()
    governor = LifecycleGovernor(tmp_path / "state.db", key, host_key=host)
    root = governor.create_domain(
        {governor.scope(Effect.EXECUTE, "tool")}, host_key=host
    )
    governor.observe(root, "host task", trusted=True, host_key=host)
    command = ("/usr/bin/true",)
    request = DispatchRequest(
        proposal={
            "capability": "process.exec",
            "operation": "execute",
            "resource": command[0],
        },
        trusted=TrustedExecutionContext("host", (Provenance.HUMAN,), "host"),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        authorized_command=command,
    )
    dispatcher = object.__new__(ProductionDispatcher)
    dispatcher.execute = lambda *a, **kw: pytest.fail("unexpected production dispatch")
    with pytest.raises(ValueError, match="differ"):
        GovernedProductionExecution(
            governor=governor,
            host_key=host,
            dispatcher=dispatcher,
            actor=root,
            target="tool",
            dispatch_request=request,
            command=("/usr/bin/false",),
            project_root=tmp_path,
        )
    bridge = GovernedProductionExecution(
        governor=governor,
        host_key=host,
        dispatcher=dispatcher,
        actor=root,
        target="tool",
        dispatch_request=request,
        command=command,
        project_root=tmp_path,
    )
    effect = bridge.request()
    token = governor.mint(effect, host_key=host)
    changed = type(effect).make(
        root, Effect.EXECUTE, "tool", {"argv": ["/usr/bin/false"]}
    )
    with pytest.raises(Rejected, match="does not match"):
        bridge.submit(changed, token)
    assert governor.snapshot()["consumed_grants"] == 0
    governor.close()
