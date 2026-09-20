from pathlib import Path
from types import SimpleNamespace
import os

import pytest

from bulldog.egress_proxy import EgressBroker
import bulldog.egress_proxy as egress_module
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
    Provenance,
)
from bulldog.namespace_sandbox import SandboxResult
from bulldog.runtime import BulldogRuntime
from bulldog.secret_broker import SecretBroker, SecretBrokerError


class AllowEngine:
    def evaluate(self, action):
        return Evaluation(
            decision=Decision.ALLOW,
            risk=0.0,
            reasons=("test allow",),
        )


class MutatingCleanScanner:
    def __init__(self, source_file: Path):
        self.source_file = source_file
        self.scanned_root = None

    def scan_project(self, root):
        self.scanned_root = Path(root)
        self.source_file.write_text("MALICIOUS", encoding="utf-8")
        return SimpleNamespace(clean=True, detections=())


class CapturingSandbox:
    def __init__(self):
        self.project_root = None
        self.resource_budget = None
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
        self.project_root = Path(project_root)
        self.resource_budget = resource_budget
        self.command = tuple(command)
        content = (self.project_root / "payload.txt").read_text(
            encoding="utf-8"
        )
        return SandboxResult(returncode=0, stdout=content, stderr="")


def _exec_action():
    return ActionRequest(
        actor="host-agent",
        task="inspect project payload with cat",
        operation="execute",
        resource="/bin/cat",
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        provenance=(Provenance.HUMAN,),
    )


def _read_action():
    return ActionRequest(
        actor="host-agent",
        task="read project",
        operation="read",
        resource="/workspace/payload.txt",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
        provenance=(Provenance.HUMAN,),
    )


def test_runtime_rejects_command_launch_without_process_exec(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "payload.txt").write_text("CLEAN", encoding="utf-8")
    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=SimpleNamespace(),
    )
    result = runtime.execute(
        _read_action(),
        ["/bin/cat", "/workspace/payload.txt"],
        project_root=project,
    )
    assert result.executed is False
    assert result.evaluation.decision == Decision.DENY
    assert result.evaluation.hard_block is True
    assert "process.exec" in result.stderr
    assert sandbox.command is None


def test_runtime_rejects_executable_resource_mismatch(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "payload.txt").write_text("CLEAN", encoding="utf-8")
    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=SimpleNamespace(),
    )
    result = runtime.execute(
        _exec_action(),
        ["/bin/sh", "-c", "echo mismatch"],
        project_root=project,
    )
    assert result.executed is False
    assert result.evaluation.decision == Decision.DENY
    assert "does not match authorized resource" in result.stderr
    assert sandbox.command is None


def test_runtime_scans_and_executes_same_immutable_snapshot(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source_file = project / "payload.txt"
    source_file.write_text("CLEAN", encoding="utf-8")
    scanner = MutatingCleanScanner(source_file)
    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=scanner,
    )
    result = runtime.execute(
        _exec_action(),
        ["/bin/cat", "/workspace/payload.txt"],
        project_root=project,
    )
    assert result.executed is True
    assert result.stdout == "CLEAN"
    assert source_file.read_text(encoding="utf-8") == "MALICIOUS"
    assert scanner.scanned_root == sandbox.project_root
    assert scanner.scanned_root != project.resolve()
    assert not sandbox.project_root.exists()


def test_runtime_passes_resource_budget_to_sandbox(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "payload.txt").write_text("CLEAN", encoding="utf-8")
    scanner = MutatingCleanScanner(project / "payload.txt")
    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=scanner,
    )
    runtime.execute(
        _exec_action(),
        ["/bin/cat", "/workspace/payload.txt"],
        project_root=project,
    )
    assert sandbox.resource_budget is runtime.resource_budget
    assert runtime.resource_budget.processes > 0
    assert runtime.resource_budget.memory_bytes > 0


def test_runtime_rejects_special_files_before_execution(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "payload.txt").write_text("CLEAN", encoding="utf-8")
    os.mkfifo(project / "danger.pipe")
    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=SimpleNamespace(),
    )
    result = runtime.execute(
        _exec_action(),
        ["/bin/cat", "/workspace/payload.txt"],
        project_root=project,
    )
    assert result.executed is False
    assert "admission/snapshot rejected" in result.stderr
    assert "special filesystem object rejected" in result.stderr
    assert sandbox.project_root is None


def test_secret_grant_is_sandbox_bound_and_one_shot(tmp_path):
    broker = SecretBroker(tmp_path / "secret.sock")
    broker.put_secret("TOKEN", "VALUE")
    grant = broker.issue_grant(
        allowed_names={"TOKEN"},
        sandbox_id="sandbox-A",
        max_uses=1,
    )
    with pytest.raises(SecretBrokerError):
        broker._authorize_and_get(grant.token, "TOKEN", sandbox_id="sandbox-B")
    assert broker._authorize_and_get(
        grant.token,
        "TOKEN",
        sandbox_id="sandbox-A",
    ) == "VALUE"
    with pytest.raises(SecretBrokerError):
        broker._authorize_and_get(grant.token, "TOKEN", sandbox_id="sandbox-A")


def test_egress_fetch_uses_validated_pinned_ip(monkeypatch, tmp_path):
    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={"example.com"},
    )
    seen = {}
    monkeypatch.setattr(
        EgressBroker,
        "_resolve_public_addresses",
        staticmethod(lambda host, port: ("93.184.216.34",)),
    )

    class FakeResponse:
        status = 200
        def read(self, n):
            return b"ok"
        def getheaders(self):
            return []

    class FakeConnection:
        def __init__(self, *, hostname, ip, port, timeout):
            seen.update({"hostname": hostname, "ip": ip, "port": port})
        def request(self, method, path, headers):
            seen["method"] = method
            seen["path"] = path
            seen["host_header"] = headers["Host"]
        def getresponse(self):
            return FakeResponse()
        def close(self):
            pass

    monkeypatch.setattr(egress_module, "_PinnedHTTPSConnection", FakeConnection)
    response = broker.fetch(method="GET", url="https://example.com/a?b=1")
    assert response.body == b"ok"
    assert seen["ip"] == "93.184.216.34"
    assert seen["hostname"] == "example.com"
    assert seen["host_header"] == "example.com"
    assert seen["path"] == "/a?b=1"


def test_mixed_public_private_dns_answers_fail_closed(monkeypatch, tmp_path):
    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={"example.com"},
    )

    def fake_getaddrinfo(*args, **kwargs):
        return [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]

    monkeypatch.setattr(egress_module.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(Exception):
        broker._resolve_public_addresses("example.com", 443)
