"""Effect-aware gateway tests with real production dispatch methods.

Only host certification and the final OS sandbox are replaced with an explicit
recording fixture. These tests establish authorization behavior, not KVM or
namespace containment. Real IPC tests are in test_gateway_transport.py.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import time
from types import SimpleNamespace

import pytest

from bulldog.agent_gateway import GatewayAuthority
from bulldog.agent_session import AgentSession
from bulldog.agent_tool_registry import validate_gateway_config
from bulldog.audit import AuditLedger
from bulldog.gateway_wire import GatewayDenied, decode_message
from bulldog.models import Capability, Decision, Evaluation
from bulldog.policy import DeterministicPolicy
from bulldog.engine import BulldogEngine
from bulldog.policy_bundle import sign_policy_bundle
from bulldog.profiles import ProductionDispatcher, ProductionRuntime
from bulldog.runtime import ExecutionResult
from bulldog.mcp_gateway import validate_rpc


def config():
    binary = Path("/usr/bin/true").resolve()
    return {
        "format": "bull-agent-gateway-v1",
        "tenant_id": "team",
        "project_id": "project",
        "session_id": "lease-1",
        "agent_uid": os.geteuid() + 1001,
        "expires_at": int(time.time()) + 3600,
        "max_calls": 10,
        "tools": [
            {
                "name": "check",
                "description": "Fixed harmless fixture",
                "operation": "process.execute",
                "argv": [str(binary)],
                "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "timeout": 5,
            }
        ],
    }


@pytest.fixture
def gateway(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    cfg = config()
    policy = tmp_path / "policy.json"

    def sign(caps=(Capability.PROCESS_EXEC,)):
        policy.write_text(
            json.dumps(
                sign_policy_bundle(
                    project_root=str(project),
                    allowed_capabilities=caps,
                    key="test-only-key",
                    agent_gateway=cfg,
                )
            )
        )

    sign()
    engine = BulldogEngine(
        ledger=AuditLedger(tmp_path / "audit.jsonl"),
        policy=DeterministicPolicy(
            project_root=str(project),
            global_capability_ceiling=frozenset({Capability.PROCESS_EXEC}),
        ),
    )
    # Use the real production binding/permit methods with a recording OS effect.
    runtime = object.__new__(ProductionRuntime)
    runtime._permit_key = b"test-only-permit"
    runtime.engine = engine
    runtime._policy_bundle_path = policy
    runtime._policy_key = "test-only-key"
    runtime.verify_trusted_state = lambda: None
    effects = []

    def execute(action, command, *, project_root, timeout, permit):
        assert runtime._valid_permit(action, command, permit)
        evaluation = engine.evaluate(action)
        executed = evaluation.decision in (Decision.ALLOW, Decision.SANDBOX)
        if executed:
            effects.append(tuple(command))
        return ExecutionResult(
            evaluation, executed, True, False, 0 if executed else None, "fixture", ""
        )

    runtime.execute = execute
    dispatcher = object.__new__(ProductionDispatcher)
    dispatcher.runtime = runtime
    dispatcher.production_mode = True
    dispatcher.freeze_on_violation = True
    dispatcher.domain_registry = None
    dispatcher.broker_engine = engine
    dispatcher.egress_broker = None
    authority = GatewayAuthority(dispatcher, state)
    fixture = SimpleNamespace(
        authority=authority,
        config=cfg,
        effects=effects,
        state=state,
        sign=sign,
        policy=policy,
    )
    yield fixture
    authority.close()


def call(g, **extra):
    message = {
        "method": "call",
        "name": "check",
        "arguments": {},
        "call_id": secrets.token_hex(16),
    }
    message.update(extra)
    return g.authority.handle(message, peer_uid=g.config["agent_uid"])


def test_fixed_command_reaches_real_production_dispatch_and_permit(gateway):
    g = gateway
    result = call(g)
    assert result["executed"] is True
    assert g.effects == [tuple(g.config["tools"][0]["argv"])]
    assert result["authorized_argv"] == list(g.effects[0])
    assert g.authority.runtime.engine.ledger.verify().valid


@pytest.mark.parametrize(
    "arguments",
    [
        {"argv": ["/bin/sh", "-c", "touch /tmp/escape"]},
        {"capability": "network.post"},
        {"uid": 0},
        {"domain_id": "other"},
        {"approval": "yes"},
        {"code": "; curl attacker.invalid"},
        {"token": "secret"},
        [],
        None,
        True,
    ],
)
def test_model_authority_and_argv_never_reach_execution(gateway, arguments):
    with pytest.raises(GatewayDenied):
        call(gateway, arguments=arguments)
    assert gateway.effects == []


@pytest.mark.parametrize(
    "extra",
    [
        {"domain_id": "other"},
        {"capability": "process.exec"},
        {"uid": 0},
        {"method": "secret.read"},
        {"name": "unknown"},
    ],
)
def test_unknown_or_spoofed_envelope_has_no_effect(gateway, extra):
    with pytest.raises(GatewayDenied):
        call(gateway, **extra)
    assert gateway.effects == []


def test_wrong_peer_cannot_even_list_tools(gateway):
    with pytest.raises(GatewayDenied, match="peer"):
        gateway.authority.handle(
            {"method": "list"}, peer_uid=gateway.config["agent_uid"] + 1
        )
    assert gateway.effects == []


def test_revocation_checked_after_menu(gateway):
    menu = gateway.authority.handle(
        {"method": "list"}, peer_uid=gateway.config["agent_uid"]
    )
    assert [x["name"] for x in menu["tools"]] == ["check"]
    (gateway.state / "REVOKED").touch()
    with pytest.raises(GatewayDenied, match="revoked"):
        call(gateway)
    assert gateway.effects == []


def test_signed_policy_change_does_not_inherit_running_authority(gateway):
    gateway.config["max_calls"] += 1
    gateway.sign()
    with pytest.raises(GatewayDenied, match="policy changed"):
        call(gateway)
    assert gateway.effects == []


def test_revocation_during_audit_precedes_effect(gateway):
    gateway.authority._audit = lambda *a, **kw: (gateway.state / "REVOKED").touch()
    with pytest.raises(GatewayDenied, match="revoked"):
        call(gateway)
    assert gateway.effects == []


def test_domain_freeze_stops_later_calls(gateway):
    gateway.authority.registry.freeze(
        gateway.authority.domain.domain_id, "operator stop"
    )
    with pytest.raises(Exception, match="frozen"):
        call(gateway)
    assert gateway.effects == []


def test_duplicate_call_id_never_reexecutes(gateway):
    ident = secrets.token_hex(16)
    assert call(gateway, call_id=ident)["executed"]
    with pytest.raises(GatewayDenied, match="replay"):
        call(gateway, call_id=ident)
    assert len(gateway.effects) == 1


def test_uncertain_effect_blocks_retry_even_with_new_call_id(gateway):
    def failed(*args, **kwargs):
        gateway.effects.append("effect occurred before disconnect")
        raise OSError("simulated lost response")

    gateway.authority.router.dispatch = failed
    with pytest.raises(OSError):
        call(gateway)
    with pytest.raises(GatewayDenied, match="uncertain"):
        call(gateway)
    assert len(gateway.effects) == 1


def test_executable_swap_is_denied(gateway, monkeypatch):
    monkeypatch.setattr("bulldog.agent_gateway.sha256_file", lambda _: "0" * 64)
    with pytest.raises(GatewayDenied, match="changed"):
        call(gateway)
    assert gateway.effects == []


def test_budget_is_consumed_before_execution(gateway):
    gateway.authority.session.config["max_calls"] = 1
    assert call(gateway)["executed"]
    with pytest.raises(GatewayDenied, match="budget"):
        call(gateway)
    assert len(gateway.effects) == 1


def test_budget_and_history_cannot_reset_on_restart(gateway):
    assert call(gateway)["executed"]
    gateway.authority.session.close()
    second = AgentSession(
        gateway.state, gateway.config, gateway.authority.policy_digest
    )
    try:
        assert second.status()["used_calls"] == 1
        with pytest.raises(GatewayDenied, match="behavioral history"):
            second.check()
    finally:
        second.close()


def test_second_authority_writer_cannot_share_lease(gateway):
    with pytest.raises(BlockingIOError):
        AgentSession(gateway.state, gateway.config, gateway.authority.policy_digest)


def test_expiry_stops_call_before_effect(gateway, monkeypatch):
    monkeypatch.setattr(
        "bulldog.agent_session.time.time", lambda: gateway.config["expires_at"]
    )
    with pytest.raises(GatewayDenied, match="expired"):
        call(gateway)
    assert gateway.effects == []


def test_clock_rollback_is_not_extra_authority(gateway, monkeypatch):
    before = time.time()
    monkeypatch.setattr("bulldog.agent_session.time.time", lambda: before - 60)
    with pytest.raises(GatewayDenied, match="backwards"):
        call(gateway)
    assert gateway.effects == []


def test_executable_alias_cannot_be_swapped_by_agent(gateway, tmp_path):
    link = tmp_path / "agent-executable"
    link.symlink_to(gateway.config["tools"][0]["argv"][0])
    gateway.authority.tools["check"]["argv"][0] = str(link)
    with pytest.raises(GatewayDenied, match="canonical"):
        call(gateway)
    assert gateway.effects == []


def test_catalog_filters_tools_outside_signed_ceiling():
    from bulldog.agent_tool_registry import available_tools

    assert available_tools(config(), frozenset({Capability.FS_READ_PROJECT})) == {}


def test_gateway_registry_signed_into_new_deployment(tmp_path):
    from tools.deployment_setup import initialize, environment, read_config
    from bulldog.policy_bundle import load_policy_bundle

    project = tmp_path / "deployed-project"
    project.mkdir()
    cfg = config()
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps(cfg))
    state = initialize(tmp_path / "deployment", project, gateway_registry=registry)
    values = environment(state)
    bundle = load_policy_bundle(
        values["BULL_POLICY_BUNDLE"], values["BULL_POLICY_BUNDLE_KEY"]
    )
    assert bundle.raw["agent_gateway"] == cfg
    assert read_config(state)[1]["agent_gateway"] == cfg


def test_signed_catalog_has_no_free_form_or_secret_adapter():
    cfg = config()
    cfg["tools"][0]["operation"] = "secret.read"
    with pytest.raises(GatewayDenied):
        validate_gateway_config(cfg)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1,"x":2}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"[]",
        b'{"x":"\\ud800"}',
        b'{"x":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
        b"x" * 32769,
    ],
)
def test_ambiguous_or_excessive_json_fails_closed(raw):
    with pytest.raises(GatewayDenied):
        decode_message(raw)


@pytest.mark.parametrize(
    "params",
    [
        {"name": "check", "arguments": {"argv": ["/bin/sh"]}},
        {"name": "check", "arguments": {}, "capability": "process.exec"},
        ["check"],
        None,
    ],
)
def test_jsonrpc_shaped_spoofs_rejected_before_sdk(params):
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
    ).encode()
    with pytest.raises(GatewayDenied):
        validate_rpc(raw)


def test_valid_jsonrpc_call_contains_no_authority():
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check","arguments":{}}}'
    assert validate_rpc(raw)["params"] == {"name": "check", "arguments": {}}
