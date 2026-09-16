from pathlib import Path
from types import SimpleNamespace

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
        # Mutate the original source after BULL has taken its snapshot.
        self.source_file.write_text("MALICIOUS", encoding="utf-8")
        return SimpleNamespace(
            clean=True,
            detections=(),
        )


class CapturingSandbox:
    def __init__(self):
        self.project_root = None
        self.resource_budget = None

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
        content = (self.project_root / "payload.txt").read_text(
            encoding="utf-8"
        )
        return SandboxResult(
            returncode=0,
            stdout=content,
            stderr="",
        )


def _action():
    return ActionRequest(
        actor="host-agent",
        task="read project",
        operation="read",
        resource="/workspace/payload.txt",
        capability=Capability.FS_READ_PROJECT,
        granted_capabilities=frozenset({
            Capability.FS_READ_PROJECT,
        }),
        provenance=(Provenance.HUMAN,),
    )


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
        _action(),
        ["ignored"],
        project_root=project,
    )

    assert result.executed is True
    assert result.stdout == "CLEAN"
    assert source_file.read_text(encoding="utf-8") == "MALICIOUS"

    # The scanner and sandbox must receive the exact same snapshot root.
    assert scanner.scanned_root == sandbox.project_root
    assert scanner.scanned_root != project.resolve()

    # Snapshot cleanup must happen even after successful execution.
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
        _action(),
        ["ignored"],
        project_root=project,
    )

    assert sandbox.resource_budget is runtime.resource_budget
    assert runtime.resource_budget.processes > 0
    assert runtime.resource_budget.memory_bytes > 0


def test_runtime_rejects_special_files_before_execution(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "payload.txt").write_text("CLEAN", encoding="utf-8")
    fifo = project / "danger.pipe"
    fifo.mkfifo()

    sandbox = CapturingSandbox()
    runtime = BulldogRuntime(
        engine=AllowEngine(),
        sandbox=sandbox,
        malware_scanner=SimpleNamespace(),
    )

    result = runtime.execute(
        _action(),
        ["ignored"],
        project_root=project,
    )

    assert result.executed is False
    assert "manifest rejected" in result.stderr
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
        broker._authorize_and_get(
            grant.token,
            "TOKEN",
            sandbox_id="sandbox-B",
        )

    assert broker._authorize_and_get(
        grant.token,
        "TOKEN",
        sandbox_id="sandbox-A",
    ) == "VALUE"

    with pytest.raises(SecretBrokerError):
        broker._authorize_and_get(
            grant.token,
            "TOKEN",
            sandbox_id="sandbox-A",
        )


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
            seen.update({
                "hostname": hostname,
                "ip": ip,
                "port": port,
            })

        def request(self, method, path, headers):
            seen["method"] = method
            seen["path"] = path
            seen["host_header"] = headers["Host"]

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        egress_module,
        "_PinnedHTTPSConnection",
        FakeConnection,
    )

    response = broker.fetch(
        method="GET",
        url="https://example.com/a?b=1",
    )

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

    monkeypatch.setattr(
        egress_module.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(Exception):
        broker._resolve_public_addresses("example.com", 443)
