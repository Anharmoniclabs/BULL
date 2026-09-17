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
