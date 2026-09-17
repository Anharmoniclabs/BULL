from pathlib import Path
from types import SimpleNamespace

import pytest

from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import (
    CapabilityDispatcher,
    DispatchDenied,
    DispatchRequest,
)
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
    Provenance,
)
from bulldog.namespace_sandbox import SandboxResult
from bulldog.runtime import BulldogRuntime, ExecutionResult
from bulldog.secret_broker import SecretBroker, SecretBrokerError
from bulldog.security_domain import (
    SecurityDomainError,
    SecurityDomainRegistry,
)


class _FakeRuntime:
    def __init__(self, evaluation):
        self.evaluation = evaluation
        self.last_action = None

    def execute(self, action, command, *, project_root, timeout):
        self.last_action = action
        return ExecutionResult(
            evaluation=self.evaluation,
            executed=False,
            sandboxed=False,
            review_required=(
                self.evaluation.decision == Decision.ESCALATE
            ),
            returncode=None,
            stdout="",
            stderr="",
        )


class _FakeEgress:
    def __init__(self):
        self.calls = []

    def fetch(self, *, method, url):
        self.calls.append((method, url))
        return SimpleNamespace(status=200, headers={}, body=b"ok")


class _AllowEngine:
    def evaluate(self, action):
        return Evaluation(
            decision=Decision.ALLOW,
            risk=0.0,
            reasons=("test allow",),
        )


class _CleanScanner:
    def scan_project(self, root):
        return SimpleNamespace(clean=True, detections=())


class _CapturingSandbox:
    def __init__(self):
        self.env = None

    def run(
        self,
        command,
        *,
        project_root,
        writable,
        timeout,
        env=None,
        resource_budget=None,
    ):
        self.env = dict(env or {})
        return SandboxResult(returncode=0, stdout="ok", stderr="")


def _legacy_trusted():
    return TrustedExecutionContext(
        actor="ignored-in-domain-mode",
        provenance=(Provenance.UNKNOWN,),
        security_context_id="ignored",
    )


def test_child_authority_and_egress_are_strict_subsets():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="inspect the repository",
        capability_ceiling={
            Capability.FS_READ_PROJECT,
            Capability.PROCESS_EXEC,
            Capability.AGENT_SPAWN,
        },
        egress_hosts={"example.com", "docs.python.org"},
    )

    child = registry.spawn_child(
        parent_domain_id=root.domain_id,
        actor="reader",
        initial_prompt="read source files",
        capability_ceiling={Capability.FS_READ_PROJECT},
        egress_hosts={"docs.python.org"},
    )

    assert child.capability_ceiling == frozenset({
        Capability.FS_READ_PROJECT
    })
    assert child.egress_hosts == frozenset({"docs.python.org"})

    with pytest.raises(SecurityDomainError):
        registry.spawn_child(
            parent_domain_id=root.domain_id,
            actor="escalating-child",
            initial_prompt="do more",
            capability_ceiling={Capability.CREDENTIAL_READ},
        )

    with pytest.raises(SecurityDomainError):
        registry.spawn_child(
            parent_domain_id=root.domain_id,
            actor="network-child",
            initial_prompt="browse",
            capability_ceiling={Capability.FS_READ_PROJECT},
            egress_hosts={"attacker.invalid"},
        )


def test_sibling_agents_share_root_behavior_context_but_not_domain_identity():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="coordinate work",
        capability_ceiling={
            Capability.FS_READ_PROJECT,
            Capability.AGENT_SPAWN,
        },
    )
    a = registry.spawn_child(
        parent_domain_id=root.domain_id,
        actor="a",
        initial_prompt="read A",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )
    b = registry.spawn_child(
        parent_domain_id=root.domain_id,
        actor="b",
        initial_prompt="read B",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )

    ctx_a = registry.trusted_context(a.domain_id)
    ctx_b = registry.trusted_context(b.domain_id)

    assert ctx_a.domain_id != ctx_b.domain_id
    assert ctx_a.root_domain_id == ctx_b.root_domain_id == root.domain_id
    assert ctx_a.security_context_id == ctx_b.security_context_id
    assert ctx_a.security_context_id == f"root-domain:{root.domain_id}"


def test_goal_transitions_require_explicit_trusted_approval():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="inspect repository",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )

    before = root.current_intent_hash
    transition = registry.transition_goal(
        root.domain_id,
        next_goal="inspect tests",
        reason="human expanded scope",
        approved_by="host:user",
    )

    assert transition.previous_intent_hash == before
    assert transition.next_intent_hash == root.current_intent_hash
    assert transition.sequence == 1

    with pytest.raises(SecurityDomainError):
        registry.transition_goal(
            root.domain_id,
            next_goal="new goal",
            reason="",
            approved_by="host:user",
        )


def test_freezing_root_stops_all_sibling_agents():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="coordinate work",
        capability_ceiling={
            Capability.FS_READ_PROJECT,
            Capability.AGENT_SPAWN,
        },
    )
    child = registry.spawn_child(
        parent_domain_id=root.domain_id,
        actor="child",
        initial_prompt="read files",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )

    registry.freeze_root(root.domain_id, "coordinated policy violation")

    with pytest.raises(SecurityDomainError):
        registry.require_active(root.domain_id)
    with pytest.raises(SecurityDomainError):
        registry.require_active(child.domain_id)


def test_dispatcher_uses_registry_identity_not_request_identity():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="host-planner",
        initial_prompt="execute approved reader",
        capability_ceiling={Capability.PROCESS_EXEC},
    )
    runtime = _FakeRuntime(
        Evaluation(
            Decision.ALLOW,
            0.0,
            ("allowed",),
        )
    )
    dispatcher = CapabilityDispatcher(
        runtime=runtime,
        domain_registry=registry,
    )

    request = DispatchRequest(
        proposal={
            "task": "run approved reader",
            "operation": "execute",
            "resource": "/bin/cat",
            "actor": "spoofed-agent",
            "domain_id": "spoofed-domain",
            "provenance": ["human"],
        },
        trusted=_legacy_trusted(),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        domain_id=root.domain_id,
    )

    dispatcher.execute(
        request,
        ["/bin/cat", "/workspace/README.md"],
        project_root="/tmp",
    )

    assert runtime.last_action.actor == "host-planner"
    assert runtime.last_action.metadata["domain_id"] == root.domain_id
    assert runtime.last_action.metadata["root_domain_id"] == root.domain_id


def test_dispatcher_rejects_authority_outside_domain_ceiling():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="reader",
        initial_prompt="read project",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )
    dispatcher = CapabilityDispatcher(
        runtime=_FakeRuntime(Evaluation(Decision.ALLOW, 0.0, ("ok",))),
        domain_registry=registry,
    )

    request = DispatchRequest(
        proposal={
            "task": "run shell",
            "operation": "execute",
            "resource": "/bin/sh",
        },
        trusted=_legacy_trusted(),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        domain_id=root.domain_id,
    )

    with pytest.raises(DispatchDenied):
        dispatcher.canonicalize(request)


def test_domain_egress_is_intersection_of_domain_and_broker_policy():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="researcher",
        initial_prompt="read docs",
        capability_ceiling={Capability.NETWORK_OUTBOUND},
        egress_hosts={"docs.python.org"},
    )
    egress = _FakeEgress()
    dispatcher = CapabilityDispatcher(
        runtime=_FakeRuntime(Evaluation(Decision.ALLOW, 0.0, ("ok",))),
        domain_registry=registry,
        egress_broker=egress,
    )

    response = dispatcher.fetch_egress(
        domain_id=root.domain_id,
        url="https://docs.python.org/3/",
    )
    assert response.status == 200

    with pytest.raises(DispatchDenied):
        dispatcher.fetch_egress(
            domain_id=root.domain_id,
            url="https://example.com/",
        )

    assert egress.calls == [("GET", "https://docs.python.org/3/")]


def test_domain_secret_grant_cannot_cross_domain_or_replay(tmp_path):
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="use API",
        capability_ceiling={Capability.CREDENTIAL_READ},
    )
    sibling = registry.create_root(
        actor="other",
        initial_prompt="other task",
        capability_ceiling={Capability.CREDENTIAL_READ},
    )

    broker = SecretBroker(tmp_path / "secret.sock")
    broker.put_secret("TOKEN", "VALUE")
    dispatcher = CapabilityDispatcher(
        runtime=_FakeRuntime(Evaluation(Decision.ALLOW, 0.0, ("ok",))),
        domain_registry=registry,
        secret_broker=broker,
    )

    grant = dispatcher.issue_domain_secret_grant(
        domain_id=root.domain_id,
        allowed_names={"TOKEN"},
        max_uses=1,
    )

    with pytest.raises(SecretBrokerError):
        broker._authorize_and_get(
            grant.token,
            "TOKEN",
            sandbox_id=sibling.domain_id,
        )

    assert broker._authorize_and_get(
        grant.token,
        "TOKEN",
        sandbox_id=root.domain_id,
    ) == "VALUE"

    with pytest.raises(SecretBrokerError):
        broker._authorize_and_get(
            grant.token,
            "TOKEN",
            sandbox_id=root.domain_id,
        )


def test_hard_block_freezes_entire_cooperating_domain_tree():
    registry = SecurityDomainRegistry()
    root = registry.create_root(
        actor="planner",
        initial_prompt="execute approved tool",
        capability_ceiling={
            Capability.FS_READ_PROJECT,
            Capability.PROCESS_EXEC,
            Capability.AGENT_SPAWN,
        },
    )
    sibling = registry.spawn_child(
        parent_domain_id=root.domain_id,
        actor="reader",
        initial_prompt="read tests",
        capability_ceiling={Capability.FS_READ_PROJECT},
    )

    runtime = _FakeRuntime(
        Evaluation(
            Decision.DENY,
            1.0,
            ("hard failure",),
            hard_block=True,
        )
    )
    dispatcher = CapabilityDispatcher(
        runtime=runtime,
        domain_registry=registry,
    )

    request = DispatchRequest(
        proposal={
            "task": "execute cat",
            "operation": "execute",
            "resource": "/bin/cat",
        },
        trusted=_legacy_trusted(),
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        domain_id=root.domain_id,
    )

    dispatcher.execute(
        request,
        ["/bin/cat", "/workspace/a.txt"],
        project_root="/tmp",
    )

    with pytest.raises(SecurityDomainError):
        registry.require_active(root.domain_id)
    with pytest.raises(SecurityDomainError):
        registry.require_active(sibling.domain_id)


def test_runtime_propagates_security_domain_binding_into_sandbox(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a.txt").write_text("hello", encoding="utf-8")

    sandbox = _CapturingSandbox()
    runtime = BulldogRuntime(
        engine=_AllowEngine(),
        sandbox=sandbox,
        malware_scanner=_CleanScanner(),
    )

    action = ActionRequest(
        actor="agent",
        task="execute cat",
        operation="execute",
        resource="/bin/cat",
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        provenance=(Provenance.HUMAN,),
        metadata={
            "domain_id": "DOMAIN",
            "root_domain_id": "ROOT",
            "parent_domain_id": "PARENT",
            "initial_intent_hash": "INTENT",
            "initial_command_hash": "COMMAND",
        },
    )

    result = runtime.execute(
        action,
        ["/bin/cat", "/workspace/a.txt"],
        project_root=project,
    )

    assert result.executed is True
    assert sandbox.env == {
        "BULL_SECURITY_DOMAIN_ID": "DOMAIN",
        "BULL_ROOT_DOMAIN_ID": "ROOT",
        "BULL_PARENT_DOMAIN_ID": "PARENT",
        "BULL_INITIAL_INTENT_HASH": "INTENT",
        "BULL_INITIAL_COMMAND_HASH": "COMMAND",
    }
