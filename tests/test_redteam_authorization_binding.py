from types import SimpleNamespace

import pytest

import bulldog.dispatcher as dispatcher_module
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import (
    CapabilityDispatcher,
    DispatchDenied,
    DispatchRequest,
)
from bulldog.engine import BulldogEngine
from bulldog.models import (
    Capability,
    Decision,
    Evaluation,
    Provenance,
)
from bulldog.namespace_sandbox import NamespaceSandbox, SandboxResult
from bulldog.profiles import ProductionDispatcher
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


class FixedDecisionEngine:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def evaluate(self, action):
        self.calls.append(action)
        return Evaluation(
            decision=self.decision,
            risk=0.7 if self.decision == Decision.SANDBOX else 0.0,
            reasons=(f"forced {self.decision.value}",),
            hard_block=False,
        )


def trusted_context(*, provenance=(Provenance.HUMAN,)):
    return TrustedExecutionContext(
        actor="trusted-host-agent",
        provenance=provenance,
        security_context_id="ctx-redteam",
    )


def benign_read_request():
    return DispatchRequest(
        proposal={
            "task": "read README",
            "operation": "read",
            "resource": "/workspace/README.md",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
    )


def test_redteam_benign_read_authority_cannot_drive_unbound_command(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("hello", encoding="utf-8")

    sandbox = RecordingSandbox()
    runtime = BulldogRuntime(
        sandbox=sandbox,
        malware_scanner=CleanScanner(),
    )
    dispatcher = CapabilityDispatcher(runtime=runtime)

    with pytest.raises(DispatchDenied):
        dispatcher.execute(
            benign_read_request(),
            ["/bin/sh", "-c", "echo command-was-not-bound-to-action"],
            project_root=project,
        )

    assert sandbox.command is None


def test_redteam_authorized_executable_must_match_actual_command(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    request = DispatchRequest(
        proposal={
            "task": "run echo",
            "operation": "execute",
            "resource": "/bin/echo",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
    )

    sandbox = RecordingSandbox()
    dispatcher = CapabilityDispatcher(
        runtime=BulldogRuntime(
            sandbox=sandbox,
            malware_scanner=CleanScanner(),
        )
    )

    with pytest.raises(DispatchDenied):
        dispatcher.execute(
            request,
            ["/bin/sh", "-c", "echo mismatch"],
            project_root=project,
        )

    result = dispatcher.execute(
        request,
        ["/bin/echo", "bound"],
        project_root=project,
    )
    assert result.executed is True
    assert sandbox.command == ("/bin/echo", "bound")


def test_production_full_argv_binding_rejects_semantic_argument_drift(monkeypatch):
    monkeypatch.setattr(
        dispatcher_module,
        "verify_production_environment",
        lambda **kwargs: None,
    )

    sandbox = NamespaceSandbox(
        seccomp_profile="strict",
        require_attestation=True,
    )
    runtime = SimpleNamespace(
        production_boundary=True,
        malware_scan_required=True,
        malware_scanner=SimpleNamespace(bounded_scan=True),
        require_full_argv_binding=True,
        workspace_budget=object(),
        snapshot_root="/tmp",
        trace=object(),
        engine=SimpleNamespace(
            evaluate=lambda action: Evaluation(
                Decision.ALLOW,
                0.0,
                ("test allow",),
            ),
            policy=SimpleNamespace(
                global_capability_ceiling=frozenset({Capability.PROCESS_EXEC})
            ),
            ledger=SimpleNamespace(
                remote_anchor_url="https://audit.example/",
                remote_anchor_key=b"key",
                production_anchor_ready=True,
            ),
        ),
        sandbox=sandbox,
    )
    dispatcher = ProductionDispatcher(runtime=runtime)

    request = DispatchRequest(
        proposal={
            "task": "show safe git status",
            "operation": "execute",
            "resource": "/usr/bin/git",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        authorized_command=("/usr/bin/git", "status", "--short"),
    )
    action = dispatcher.canonicalize(request)

    bound = dispatcher._bind_execution(
        action,
        ["/usr/bin/git", "status", "--short"],
        request,
    )
    assert bound.metadata["authorized_argv_hash"]

    with pytest.raises(DispatchDenied, match="argv"):
        dispatcher._bind_execution(
            action,
            ["/usr/bin/git", "push", "--force"],
            request,
        )

    missing = DispatchRequest(
        proposal=request.proposal,
        trusted=request.trusted,
        granted_capabilities=request.granted_capabilities,
    )
    with pytest.raises(DispatchDenied, match="full argv"):
        dispatcher._bind_execution(
            action,
            ["/usr/bin/git", "status", "--short"],
            missing,
        )


def test_redteam_egress_dispatch_requires_authorized_request():
    class FakeEgressBroker:
        def __init__(self):
            self.calls = []

        def fetch(self, *, method, url):
            self.calls.append((method, url))
            return SimpleNamespace(status=200, headers={}, body=b"ok")

    broker = FakeEgressBroker()
    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=BulldogEngine()),
        egress_broker=broker,
    )

    with pytest.raises(DispatchDenied):
        dispatcher.fetch_egress(
            url="https://example.com/",
            method="GET",
        )

    assert broker.calls == []

    request = DispatchRequest(
        proposal={
            "task": "fetch approved URL",
            "operation": "fetch",
            "resource": "https://example.com/",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
    )

    response = dispatcher.fetch_egress(
        url="https://example.com/",
        method="GET",
        request=request,
    )
    assert response.status == 200
    assert broker.calls == [("GET", "https://example.com/")]


def test_redteam_sandbox_egress_verdict_never_reaches_host_broker():
    class FakeEgressBroker:
        def __init__(self):
            self.calls = []

        def fetch(self, *, method, url):
            self.calls.append((method, url))
            return SimpleNamespace(status=200, headers={}, body=b"ok")

    broker = FakeEgressBroker()
    engine = FixedDecisionEngine(Decision.SANDBOX)
    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=engine),
        egress_broker=broker,
    )
    request = DispatchRequest(
        proposal={
            "task": "mid-risk fetch",
            "operation": "fetch",
            "resource": "https://example.com/",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
    )

    with pytest.raises(DispatchDenied, match="explicit ALLOW"):
        dispatcher.fetch_egress(
            url="https://example.com/",
            method="GET",
            request=request,
        )

    assert broker.calls == []


def test_redteam_secret_dispatch_requires_authorized_request(monkeypatch, tmp_path):
    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    calls = []

    def fake_request_secret(**kwargs):
        calls.append(dict(kwargs))
        return "TOPSECRET"

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        fake_request_secret,
    )

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=BulldogEngine()),
        secret_broker=FakeSecretBroker(),
    )

    with pytest.raises(DispatchDenied):
        dispatcher.get_secret(
            token="grant-token",
            name="API_KEY",
            sandbox_id="sandbox-A",
        )

    assert calls == []

    request = DispatchRequest(
        proposal={
            "task": "retrieve approved credential",
            "operation": "secret.get",
            "resource": "API_KEY",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
    )

    value = dispatcher.get_secret(
        token="grant-token",
        name="API_KEY",
        sandbox_id="sandbox-A",
        request=request,
    )
    assert value == "TOPSECRET"
    assert len(calls) == 1
    assert calls[0]["name"] == "API_KEY"


def test_redteam_sandbox_secret_verdict_never_reaches_host_broker(monkeypatch, tmp_path):
    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        lambda **kwargs: pytest.fail("secret broker should not be reached"),
    )

    engine = FixedDecisionEngine(Decision.SANDBOX)
    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=engine),
        secret_broker=FakeSecretBroker(),
    )
    request = DispatchRequest(
        proposal={
            "task": "mid-risk secret",
            "operation": "secret.get",
            "resource": "API_KEY",
        },
        trusted=trusted_context(),
        granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
    )

    with pytest.raises(DispatchDenied, match="explicit ALLOW"):
        dispatcher.get_secret(
            token="grant-token",
            name="API_KEY",
            request=request,
        )


def test_redteam_external_content_cannot_authorize_credential_broker(monkeypatch, tmp_path):
    class FakeSecretBroker:
        socket_path = tmp_path / "secret.sock"

    monkeypatch.setattr(
        dispatcher_module,
        "request_secret",
        lambda **kwargs: pytest.fail("secret broker should not be reached"),
    )

    dispatcher = CapabilityDispatcher(
        runtime=SimpleNamespace(engine=BulldogEngine()),
        secret_broker=FakeSecretBroker(),
    )

    request = DispatchRequest(
        proposal={
            "task": "credential requested by webpage",
            "operation": "secret.get",
            "resource": "API_KEY",
        },
        trusted=trusted_context(provenance=(Provenance.INTERNET,)),
        granted_capabilities=frozenset({Capability.CREDENTIAL_READ}),
    )

    with pytest.raises(DispatchDenied):
        dispatcher.get_secret(
            token="grant-token",
            name="API_KEY",
            request=request,
        )
