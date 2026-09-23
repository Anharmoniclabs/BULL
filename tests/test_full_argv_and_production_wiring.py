from __future__ import annotations

from types import SimpleNamespace

import pytest

from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.models import ActionRequest, Capability, Provenance
from bulldog.namespace_sandbox import SandboxResult
from bulldog.profiles import ProductionDispatcher
from bulldog.runtime import BulldogRuntime
from bulldog.security_domain import hash_command


class CleanScanner:
    def scan_project(self, root):
        return SimpleNamespace(clean=True, detections=())


class RecordingSandbox:
    def __init__(self):
        self.command = None

    def run(
        self,
        command,
        *,
        project_root,
        writable,
        timeout,
        resource_budget=None,
        **kwargs,
    ):
        self.command = tuple(command)
        return SandboxResult(returncode=0, stdout="ok", stderr="")


def _action(argv):
    return ActionRequest(
        actor="host",
        task="authorized command",
        operation="execute",
        resource=argv[0],
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        provenance=(Provenance.HUMAN,),
        metadata={"authorized_argv_hash": str(hash_command(argv))},
    )


def test_runtime_full_argv_binding_denies_argument_drift_before_execution(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.txt").write_text("safe", encoding="utf-8")

    sandbox = RecordingSandbox()
    runtime = BulldogRuntime(
        sandbox=sandbox,
        malware_scanner=CleanScanner(),
        require_full_argv_binding=True,
    )

    action = _action(("/bin/echo", "safe"))
    result = runtime.execute(
        action,
        ["/bin/echo", "different"],
        project_root=project,
    )

    assert result.executed is False
    assert result.evaluation.hard_block is True
    assert "argv" in result.stderr
    assert sandbox.command is None


def test_runtime_full_argv_binding_allows_exact_authorized_vector(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.txt").write_text("safe", encoding="utf-8")

    sandbox = RecordingSandbox()
    runtime = BulldogRuntime(
        sandbox=sandbox,
        malware_scanner=CleanScanner(),
        require_full_argv_binding=True,
    )

    argv = ("/bin/echo", "safe")
    result = runtime.execute(
        _action(argv),
        list(argv),
        project_root=project,
    )

    assert result.executed is True
    assert sandbox.command == argv


def test_legacy_production_boolean_is_never_a_production_boundary():
    hardened_looking_runtime = SimpleNamespace(
        production_boundary=True,
        malware_scan_required=True,
        malware_scanner=SimpleNamespace(bounded_scan=True),
        require_full_argv_binding=True,
        workspace_budget=object(),
        snapshot_root="/tmp",
        trace=object(),
        engine=SimpleNamespace(
            evaluate=lambda action: None,
            policy=SimpleNamespace(global_capability_ceiling=frozenset({Capability.PROCESS_EXEC})),
            ledger=SimpleNamespace(
                remote_anchor_url="https://audit.example/",
                remote_anchor_key=b"key",
            ),
        ),
        sandbox=SimpleNamespace(seccomp_profile="strict", require_attestation=True),
    )

    with pytest.raises(DispatchDenied, match="ProductionDispatcher"):
        CapabilityDispatcher(
            runtime=hardened_looking_runtime,
            production_mode=True,
        )


def test_production_dispatcher_rejects_nonproduction_runtime_marker():
    fake_runtime = SimpleNamespace(production_boundary=False)
    with pytest.raises(DispatchDenied, match="ProductionRuntime"):
        ProductionDispatcher(runtime=fake_runtime)


@pytest.mark.parametrize("production", [False, True])
def test_empty_grant_returns_denial_without_sandbox_effect(tmp_path, production):
    """Issue #51: a returned ExecutionResult is not evidence of execution.

    Production construction/host checks are stubbed here; real policy, dispatch
    binding, permits and runtime denial run against a recording sandbox.
    """
    from bulldog.canonicalizer import TrustedExecutionContext
    from bulldog.dispatcher import DispatchRequest
    from bulldog.models import Decision
    from bulldog.profiles import ProductionRuntime

    sandbox = RecordingSandbox()
    runtime = object.__new__(ProductionRuntime) if production else object.__new__(BulldogRuntime)
    BulldogRuntime.__init__(runtime, sandbox=sandbox, malware_scanner=CleanScanner(),
                            require_full_argv_binding=production)
    if production:
        runtime._permit_key = b"test-only-dispatch-permit-key-0000"
        runtime.verify_trusted_state = lambda: None
    dispatcher = object.__new__(ProductionDispatcher if production else CapabilityDispatcher)
    dispatcher.runtime = runtime
    dispatcher.production_mode = production
    dispatcher.domain_registry = None
    dispatcher.freeze_on_violation = True
    request = DispatchRequest(
        proposal={"capability": "process.exec", "operation": "execute", "resource": "/usr/bin/true"},
        trusted=TrustedExecutionContext("fixture", (Provenance.HUMAN,), "fixture"),
        granted_capabilities=frozenset(), authorized_command=("/usr/bin/true",))
    result = dispatcher.execute(request, ["/usr/bin/true"], project_root=tmp_path)
    assert result.evaluation.decision == Decision.DENY
    assert result.executed is False
    assert sandbox.command is None


@pytest.mark.parametrize("actual,authorized", [
    (("/usr/bin/true",), None),
    (("/usr/bin/true", "extra"), ("/usr/bin/true",)),
    (("/usr/bin/false",), ("/usr/bin/true",)),
])
def test_production_binding_rejects_unauthorized_vector_before_runtime(tmp_path, actual, authorized):
    from bulldog.canonicalizer import TrustedExecutionContext
    from bulldog.dispatcher import DispatchRequest

    calls = []
    dispatcher = object.__new__(ProductionDispatcher)
    dispatcher.production_mode = True
    dispatcher.domain_registry = None
    dispatcher.runtime = SimpleNamespace(verify_trusted_state=lambda: None,
                                        execute=lambda *a, **kw: calls.append(kw))
    request = DispatchRequest(
        proposal={"capability": "process.exec", "operation": "execute", "resource": "/usr/bin/true"},
        trusted=TrustedExecutionContext("fixture", (Provenance.HUMAN,), "fixture"),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}), authorized_command=authorized)
    with pytest.raises(DispatchDenied):
        dispatcher.execute(request, actual, project_root=tmp_path)
    assert calls == []
