"""Local audit/profile acceptance. OS enforcement still needs a live host run."""

from dataclasses import asdict
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from bulldog.audit import AuditIntegrityError
from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied
from bulldog.local_audit import (
    LocalAuditLedger,
    local_ledger_from_environment,
    private_key,
)
from bulldog.local_gate import evaluate_local_environment
from bulldog.production_router import (
    LocalEffectRouter,
    ProductionEffect,
    ProductionEffectRouter,
)
from bulldog.profiles import (
    LocalDispatcher,
    LocalRuntime,
    ProductionDispatcher,
    ProductionRuntime,
)
from tools import deployment_setup as setup
from tools import run_codespace_agent_gateway as runner
from tools.qualify_agent_gateway import validate_audit_mode


def install(tmp_path, name="local"):
    project = tmp_path / (name + "-project")
    project.mkdir()
    return setup.initialize(tmp_path / name, project, audit_mode="local")


def ledger_for(state):
    return LocalAuditLedger(
        state / "audit/ledger.jsonl",
        anchor_path=state / "audit/local-checkpoint.json",
        anchor_key=private_key(state / "secrets/local-audit.key"),
    )


def test_local_installs_need_no_remote_key_and_never_inherit_one(tmp_path, monkeypatch):
    monkeypatch.setenv("BULL_ANCHOR_MASTER_KEY", "someone-elses-test-key")
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_URL", "https://unwanted.invalid")
    first, second = install(tmp_path), install(tmp_path, "second")
    a, b = ledger_for(first), ledger_for(second)
    assert a.anchor_key != b.anchor_key
    env = setup.isolated_environment(first)
    assert env["BULL_AUDIT_MODE"] == "local"
    assert "BULL_ANCHOR_MASTER_KEY" not in env
    assert "BULL_REMOTE_AUDIT_ANCHOR_URL" not in env
    assert "BULL_REMOTE_AUDIT_ANCHOR_KEY" not in env
    assert "BULL_AUDIT_TRANSPORT" not in env
    assert not (first / "secrets/collector.key").exists()
    assert a.local_anchor_ready and not a.production_anchor_ready
    assert a.remote_anchor_url is None and a.transport is None
    a.append_event("local_test", {"purpose": "fixture only"})
    assert not a.remote_checkpoint_path.exists()
    assert a.verify().records == 1


@pytest.mark.parametrize(
    "damage", ["delete", "mac", "stale", "truncate", "erase_log_and_head"]
)
def test_local_checkpoint_failure_blocks_further_effect_audits(tmp_path, damage):
    ledger = ledger_for(install(tmp_path))
    initial = ledger.anchor_path.read_bytes()
    ledger.append_event("attempt", {"fixture": True})
    if damage == "delete":
        ledger.anchor_path.unlink()
    elif damage == "mac":
        record = json.loads(ledger.anchor_path.read_text())
        ledger.anchor_path.write_text(json.dumps({**record, "mac": "0" * 64}))
    elif damage == "stale":
        ledger.anchor_path.write_bytes(initial)
    elif damage == "truncate":
        ledger.path.write_text("")
    else:
        ledger.path.unlink()
        ledger.head_path.unlink()
    assert not ledger.verify().valid
    with pytest.raises(AuditIntegrityError):
        ledger.append_event("must_not_continue", {})


def test_deleted_zero_checkpoint_cannot_be_silently_reinitialized(tmp_path):
    ledger = ledger_for(install(tmp_path))
    ledger.anchor_path.unlink()
    with pytest.raises(AuditIntegrityError, match="missing"):
        ledger.append_event("initial", {})


def test_wrong_installation_key_cannot_authenticate_local_log(tmp_path):
    first, second = install(tmp_path), install(tmp_path, "other")
    ledger = ledger_for(first)
    ledger.append_event("attempt", {})
    ledger.anchor_key = ledger_for(second).anchor_key
    assert not ledger.local_anchor_ready


@pytest.mark.parametrize("mutation", ["public", "symlink", "hardlink"])
def test_local_key_must_be_private_and_single_link(tmp_path, mutation):
    key = install(tmp_path) / "secrets/local-audit.key"
    if mutation == "public":
        key.chmod(0o644)
    elif mutation == "symlink":
        link = key.with_name("link")
        link.symlink_to(key)
        key = link
    else:
        os.link(key, key.with_name("link"))
    with pytest.raises(ValueError):
        private_key(key)


@pytest.mark.parametrize("profile", ["local", "external"])
def test_audit_qualification_cannot_accept_the_other_profile(profile):
    other = "external" if profile == "local" else "local"
    validate_audit_mode({"audit_mode": profile}, profile)
    for coverage in ({}, {"audit_mode": other}):
        with pytest.raises(ValueError, match="profile"):
            validate_audit_mode(coverage, profile)


def test_local_runtime_cannot_satisfy_production_types():
    local = object.__new__(LocalRuntime)
    external = object.__new__(ProductionRuntime)
    assert local.production_boundary is False
    with pytest.raises(DispatchDenied, match="ProductionRuntime"):
        ProductionDispatcher(runtime=local)
    with pytest.raises(DispatchDenied, match="LocalRuntime"):
        LocalDispatcher(runtime=external)
    with pytest.raises(TypeError, match="ProductionDispatcher"):
        ProductionEffectRouter(object.__new__(LocalDispatcher))
    with pytest.raises(TypeError, match="LocalDispatcher"):
        LocalEffectRouter(object.__new__(ProductionDispatcher))
    with pytest.raises(DispatchDenied, match="LocalDispatcher"):
        CapabilityDispatcher(runtime=local, local_mode=True)


def test_local_runtime_assembles_enforcement_without_external_transport(
    tmp_path, monkeypatch
):
    from bulldog import local_gate, profiles

    state = install(tmp_path)
    monkeypatch.setattr(os, "environ", setup.isolated_environment(state))
    # Only host certification and scanner availability are fixtures here.
    # No command is executed, and this is not containment evidence.
    monkeypatch.setattr(local_gate, "verify_local_environment", lambda **kwargs: None)
    monkeypatch.setattr(
        profiles, "MalwareScanner", lambda **kwargs: SimpleNamespace(bounded_scan=True)
    )

    def forbidden():
        raise AssertionError("local assembly contacted external audit configuration")

    monkeypatch.setattr(profiles, "production_transport_from_environment", forbidden)
    runtime = LocalRuntime()
    dispatcher = LocalDispatcher(runtime=runtime)
    assert dispatcher.local_mode and not dispatcher.production_mode
    assert runtime.require_full_argv_binding and runtime.malware_scan_required
    assert runtime.sandbox.seccomp_profile == "strict"
    assert runtime.sandbox.require_attestation is True
    assert runtime.snapshot_root == state / "snapshots"
    runtime.verify_trusted_state()
    # A production-looking environment cannot make a broken local ledger pass.
    (state / "audit/local-checkpoint.json").unlink()
    with pytest.raises(DispatchDenied, match="local audit"):
        LocalDispatcher(runtime=runtime)


@pytest.mark.parametrize(
    "mode,gid,ready",
    [
        (0o600, 1001, False),
        (0o666, 1001, False),
        (0o660, 1000, False),
        (0o660, 1001, True),
    ],
)
def test_endpoint_waits_for_agent_permissions(mode, gid, ready):
    import stat

    path = SimpleNamespace(
        lstat=lambda: SimpleNamespace(
            st_mode=stat.S_IFSOCK | mode, st_uid=1000, st_gid=gid
        )
    )
    assert runner.endpoint_ready(path, 1000, 1001) is ready


@pytest.mark.parametrize(
    "operation", ["network.request", "secret.read", "publish", "message.send"]
)
def test_local_effect_router_cannot_reach_external_brokers(operation):
    router = LocalEffectRouter(object.__new__(LocalDispatcher))
    with pytest.raises(DispatchDenied):
        router.dispatch(ProductionEffect(operation, None, {}))


def test_local_gates_keep_every_execution_requirement(tmp_path, monkeypatch):
    from bulldog import local_gate

    state = install(tmp_path)
    for key, value in setup.isolated_environment(state, {}).items():
        monkeypatch.setenv(key, value)
    assert local_ledger_from_environment().local_anchor_ready
    captured = []

    def host_checks(requirements, **kwargs):
        captured.append(asdict(requirements))
        return {"passed": True, "checks": [], "failures": []}

    monkeypatch.setattr(local_gate, "evaluate_production_environment", host_checks)
    report = evaluate_local_environment()
    assert report["format"] == "bull-local-gate-evidence-v1"
    assert report["passed"] is True
    assert captured[0].pop("require_remote_audit_anchor") is False
    assert all(captured[0].values())
    (state / "audit/local-checkpoint.json").unlink()
    assert evaluate_local_environment()["passed"] is False


def test_no_secret_discovery_during_local_preflight(monkeypatch, capsys):
    monkeypatch.setattr(runner, "host_checks", lambda: {"fixture_host": True})

    def forbidden(*a, **kw):
        raise AssertionError("local must not discover or select external credentials")

    monkeypatch.setattr(runner, "collector_configuration", forbidden)
    monkeypatch.setattr(runner, "select_collector", forbidden)
    monkeypatch.setattr(runner.sys, "argv", ["local-runner", "--preflight"])
    assert runner.main(default_local=True) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "READY_FOR_LOCAL_CHECKS"
    assert report["collector_configuration"]["external_collector_required"] is False


def test_local_does_not_silently_replace_explicit_external_inputs():
    args = SimpleNamespace(
        local=True,
        deployment="private/state",
        collector_url=None,
        collector_key_file=None,
        collector_from_env=False,
    )
    with pytest.raises(ValueError, match="choose local"):
        runner.select_audit(args, None)


def test_local_retained_audit_matches_the_actual_mcp_result(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    state = setup.initialize(
        tmp_path / "private/deployment", project, audit_mode="local"
    )
    ledger = ledger_for(state)
    result = {"call_id": "a" * 32, "result_sha256": "b" * 64}
    ledger.append_event("gateway_attempt", {"call_id": result["call_id"]})
    ledger.append_event(
        "gateway_result",
        {
            "call_id": result["call_id"],
            "executed": True,
            "result_digest": result["result_sha256"],
        },
    )
    report = runner.verify_retained_audit(tmp_path, result, audit_mode="local")
    assert report["records"] == 2 and report["external_receipt"] is False
    with pytest.raises(ValueError, match="not bound"):
        runner.verify_retained_audit(
            tmp_path, {**result, "call_id": "c" * 32}, audit_mode="local"
        )
    with pytest.raises(FileNotFoundError):
        runner.verify_retained_audit(tmp_path, result, audit_mode="external")


def test_external_url_cannot_be_added_to_an_existing_local_deployment(tmp_path):
    state = install(tmp_path)
    with pytest.raises(ValueError, match="separate deployment"):
        setup.configure(state, url="https://collector.example/checkpoints")


@pytest.mark.parametrize(
    "inputs",
    [
        {"url": "https://collector.example/checkpoints"},
        {"existing_collector_key": "/private/key"},
        {"capabilities": ["network.outbound"]},
    ],
)
def test_local_install_rejects_external_authority(tmp_path, inputs):
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError):
        setup.initialize(tmp_path / "state", project, audit_mode="local", **inputs)
    assert not (tmp_path / "state").exists()
