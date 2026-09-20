from types import SimpleNamespace

import pytest

from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance
from bulldog.policy import DeterministicPolicy
from bulldog.profiles import DevelopmentRuntime, ProductionRuntime
from bulldog.security_domain import hash_command
from bulldog.trace_runtime import RuntimeTraceVerifier


def _exec_action(argv=("/usr/bin/true",)):
    return ActionRequest(
        actor="host",
        task="redteam",
        operation="execute",
        resource=argv[0],
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        provenance=(Provenance.HUMAN,),
        metadata={"authorized_argv_hash": str(hash_command(argv))},
    )


def test_legacy_production_boolean_is_rejected():
    with pytest.raises(DispatchDenied, match="ProductionDispatcher"):
        CapabilityDispatcher(production_mode=True)


def test_development_runtime_is_loudly_marked_unsafe():
    with pytest.warns(RuntimeWarning, match="UNSAFE DEVELOPMENT MODE"):
        runtime = DevelopmentRuntime(
            sandbox=SimpleNamespace(),
            malware_scan_required=False,
        )
    assert runtime.require_full_argv_binding is False


def test_production_runtime_rejects_caller_supplied_security_components():
    with pytest.raises(TypeError, match="does not accept caller-supplied"):
        ProductionRuntime(engine=BulldogEngine())


def test_direct_production_runtime_call_has_no_execution_authority(tmp_path):
    runtime = ProductionRuntime.__new__(ProductionRuntime)
    runtime._permit_key = b"P" * 32
    runtime.trace = RuntimeTraceVerifier()
    runtime.engine = BulldogEngine()

    action = _exec_action()
    result = ProductionRuntime.execute(
        runtime,
        action,
        ["/usr/bin/true"],
        project_root=tmp_path,
    )
    assert result.executed is False
    assert result.evaluation.decision == Decision.DENY
    assert result.evaluation.hard_block is True
    assert "dispatcher-minted" in result.stderr


def test_dispatch_permit_is_bound_to_action_and_exact_argv(tmp_path):
    runtime = ProductionRuntime.__new__(ProductionRuntime)
    runtime._permit_key = b"Q" * 32
    runtime.trace = RuntimeTraceVerifier()
    runtime.engine = BulldogEngine()

    action = _exec_action(("/usr/bin/true",))
    permit = runtime._mint_dispatch_permit(action, ["/usr/bin/true"])
    assert runtime._valid_permit(action, ["/usr/bin/true"], permit) is True
    assert runtime._valid_permit(action, ["/usr/bin/true", "extra"], permit) is False

    changed = ActionRequest(
        actor="different",
        task=action.task,
        operation=action.operation,
        resource=action.resource,
        capability=action.capability,
        granted_capabilities=action.granted_capabilities,
        provenance=action.provenance,
        metadata=action.metadata,
    )
    assert runtime._valid_permit(changed, ["/usr/bin/true"], permit) is False


def test_signed_deployment_policy_is_a_global_capability_ceiling():
    policy = DeterministicPolicy(
        global_capability_ceiling=frozenset({Capability.FS_READ_PROJECT})
    )
    result = policy.evaluate(_exec_action())
    assert result.decision == Decision.DENY
    assert result.hard_block is True
    assert "deployment policy" in result.reasons[0]
