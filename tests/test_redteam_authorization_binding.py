from pathlib import Path
from types import SimpleNamespace

import pytest

import bulldog.dispatcher as dispatcher_module
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import CapabilityDispatcher, DispatchRequest
from bulldog.models import Capability, Provenance
from bulldog.namespace_sandbox import SandboxResult
from bulldog.runtime import BulldogRuntime


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
        return SandboxResult(returncode=0, stdout="ran", stderr="")


def benign_read_request():
    return DispatchRequest(
        proposal={
            "task": "read README",
            "operation": "read",
            "resource": "/workspace/README.md",
        },
        trusted=TrustedExecutionContext(
            actor="trusted-host-agent",
            provenance=(Provenance.HUMAN,),
            security_context_id="ctx-redteam",
        ),
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
    )


def test_redteam_benign_read_authority_cannot_drive_unbound_command(tmp_path):
    """A read capability must not authorize an unrelated executable command."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("hello", encoding="utf-8")

    sandbox = RecordingSandbox()
    runtime = BulldogRuntime(
        sandbox=sandbox,
        malware_scanner=CleanScanner(),
    )
    dispatcher = CapabilityDispatcher(runtime=runtime)

    result = dispatcher.execute(
        benign_read_request(),
        ["/bin/sh", "-c", "echo command-was-not-bound-to-action"],
        project_root=project,
    )

    if result.executed and sandbox.command and sandbox.command[0] == "/bin/sh":
        pytest.fail(
            "BYPASS CONFIRMED: FS_READ_PROJECT approval was not bound to the "
            "actual command; an unrelated shell command reached the sandbox."
        )


def test_redteam_egress_dispatch_requires_authorized_request():
    """Broker egress should pass through the same capability reference monitor."""

    class FakeEgressBroker:
        def fetch(self, *, method, url):
            return SimpleNamespace(status=200, headers={}, body=b"ok")

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(),
        egress_broker=FakeEgressBroker(),
    )

    response = dispatcher.fetch_egress(
        url="https://example.com/",
        method="GET",
    )

    if response.status == 200:
        pytest.fail(
            "BYPASS CONFIRMED: dispatcher.fetch_egress performed brokered "
            "network access without any DispatchRequest/capability check."
        )


def test_redteam_secret_dispatch_requires_authorized_request(monkeypatch, tmp_path):
    """Secret retrieval should require an authorized credential-read request."""

    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        lambda **kwargs: "TOPSECRET",
    )

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(),
        secret_broker=FakeSecretBroker(),
    )

    value = dispatcher.get_secret(
        token="grant-token",
        name="API_KEY",
        sandbox_id="sandbox-A",
    )

    if value == "TOPSECRET":
        pytest.fail(
            "BYPASS CONFIRMED: dispatcher.get_secret returned a secret without "
            "any DispatchRequest/capability/provenance authorization check."
        )
