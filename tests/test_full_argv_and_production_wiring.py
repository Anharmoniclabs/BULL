from __future__ import annotations

from types import SimpleNamespace

import pytest

import bulldog.dispatcher as dispatcher_module
from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.models import (
    ActionRequest,
    Capability,
    Provenance,
)
from bulldog.namespace_sandbox import SandboxResult
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


def test_production_dispatcher_rejects_runtime_without_hardened_wiring(monkeypatch):
    monkeypatch.setattr(
        dispatcher_module,
        "verify_production_environment",
        lambda **kwargs: None,
    )

    insecure_runtime = SimpleNamespace(
        malware_scan_required=True,
        malware_scanner=object(),
        require_full_argv_binding=False,
        trace=object(),
        sandbox=SimpleNamespace(
            seccomp_profile="strict",
            require_attestation=True,
        ),
    )

    with pytest.raises(DispatchDenied, match="full argv"):
        CapabilityDispatcher(
            runtime=insecure_runtime,
            production_mode=True,
        )


def test_production_dispatcher_rejects_compat_seccomp_runtime(monkeypatch):
    monkeypatch.setattr(
        dispatcher_module,
        "verify_production_environment",
        lambda **kwargs: None,
    )

    insecure_runtime = SimpleNamespace(
        malware_scan_required=True,
        malware_scanner=object(),
        require_full_argv_binding=True,
        trace=object(),
        sandbox=SimpleNamespace(
            seccomp_profile="compat",
            require_attestation=True,
        ),
    )

    with pytest.raises(DispatchDenied, match="strict seccomp"):
        CapabilityDispatcher(
            runtime=insecure_runtime,
            production_mode=True,
        )
