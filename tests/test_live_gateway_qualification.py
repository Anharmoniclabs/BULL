"""Evidence acceptance and collector selection; these fixtures are not a live run."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from bulldog.anchor_service import AnchorError, authenticate, session_key
from bulldog.audit import AuditLedger
from tools import run_codespace_agent_gateway as runner
from tools.qualify_agent_gateway import validate_execution_result


def completed():
    return {
        "executed": True,
        "status": "COMPLETED",
        "decision": "ALLOW",
        "authorized_argv": ["/usr/bin/true"],
        "returncode": 0,
    }


def test_zero_exit_of_exact_command_is_required():
    validate_execution_result(completed(), ["/usr/bin/true"])


@pytest.mark.parametrize(
    "change",
    [
        {"executed": False},
        {"authorized_argv": ["/bin/sh"]},
        {"returncode": 1},
        {"returncode": False},
        {"returncode": None},
        {"decision": "DENY"},
        {"status": "DENIED"},
    ],
)
def test_success_shaped_response_cannot_hide_wrong_or_failed_effect(change):
    with pytest.raises(ValueError):
        validate_execution_result({**completed(), **change}, ["/usr/bin/true"])


def options(**values):
    return SimpleNamespace(
        deployment=None, collector_url=None, collector_key_file=None, **values
    )


def deployment(home, name):
    state = home / ".local/share/bull" / name
    state.mkdir(parents=True, mode=0o700)
    runner.write_json(
        state / "deployment.json",
        {
            "format": "bull-deployment-config-v1",
            "collector_url": "https://collector.example.invalid/v1/checkpoints",
        },
    )
    (state / "secrets").mkdir(mode=0o700)
    key = state / "secrets/collector.key"
    key.write_bytes(b"fixture-key-with-exact-newline-123456789\n")
    key.chmod(0o600)
    return state


def test_selects_one_existing_operator_collector_without_rewriting_it(tmp_path):
    state = deployment(tmp_path, "deployment-01")
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    url, key = runner.select_collector(options(), user)
    assert url == "https://collector.example.invalid/v1/checkpoints"
    assert key == state / "secrets/collector.key"
    assert key.read_bytes().endswith(b"\n")


def test_ambiguous_collector_requires_an_explicit_selection(tmp_path):
    deployment(tmp_path, "deployment-01")
    deployment(tmp_path, "deployment-02")
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="select one"):
        runner.select_collector(options(), user)


def test_local_collector_and_public_key_file_cannot_qualify(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"test-only-key" * 4)
    key.chmod(0o600)
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    args = options()
    args.collector_url, args.collector_key_file = "https://127.0.0.1/", key
    with pytest.raises(ValueError, match="non-local"):
        runner.select_collector(args, user)
    args.collector_url = "https://collector.example.invalid/"
    key.chmod(0o644)
    with pytest.raises(ValueError, match="private input"):
        runner.select_collector(args, user)


def test_symlink_collector_key_is_rejected(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"test-only-key" * 4)
    key.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(key)
    with pytest.raises(ValueError, match="without symlinks"):
        runner.private_path(link, os.getuid())


@pytest.fixture
def collector_env(monkeypatch):
    monkeypatch.setenv(
        "BULL_REMOTE_AUDIT_ANCHOR_URL",
        "https://collector.example.invalid/v1/checkpoints",
    )
    raw = b"private-test-fixture-never-an-actual-key\n"
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_KEY", raw.decode())
    monkeypatch.delenv("BULL_DEPLOYMENT_ANCHOR_KEY_FILE", raising=False)
    monkeypatch.delenv("BULL_ANCHOR_MASTER_KEY", raising=False)
    return raw


def test_environment_requires_explicit_selection(tmp_path, collector_env):
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="select one"):
        runner.select_collector(options(), user)


def test_environment_preflight_has_no_secret_values_or_file_writes(
    tmp_path, collector_env, monkeypatch, capsys
):
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    monkeypatch.setattr(runner.pwd, "getpwuid", lambda uid: user)
    monkeypatch.setattr(runner, "host_checks", lambda: {"fixture_host": True})
    monkeypatch.setattr(
        runner.sys, "argv", ["runner", "--preflight", "--collector-from-env"]
    )
    assert runner.main() == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["checks"]["external_collector_configured"] is True
    assert report["status"] == "READY_FOR_PRODUCTION_CHECKS"
    assert collector_env.decode().strip() not in output
    assert "collector.example.invalid" not in output
    assert list(tmp_path.iterdir()) == []


def test_injected_key_keeps_exact_bytes_and_private_permissions(
    tmp_path, collector_env
):
    tmp_path.chmod(0o700)
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    destination = tmp_path / "collector.key"
    _, key = runner.select_collector(
        options(collector_from_env=True), user, secret_destination=destination
    )
    assert key == destination
    assert key.read_bytes() == collector_env
    assert key.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        runner.select_environment_collector(user, destination)
    assert key.read_bytes() == collector_env


def test_environment_file_and_value_must_agree(tmp_path, collector_env, monkeypatch):
    key = tmp_path / "key"
    key.write_bytes(collector_env)
    key.chmod(0o600)
    monkeypatch.setenv("BULL_DEPLOYMENT_ANCHOR_KEY_FILE", str(key))
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    assert runner.select_environment_collector(user)[1] == key
    key.write_bytes(b"different-private-test-fixture-value")
    with pytest.raises(ValueError, match="disagree"):
        runner.select_environment_collector(user)


def test_worker_named_secret_is_an_explicit_alias(tmp_path, collector_env, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.delenv("BULL_REMOTE_AUDIT_ANCHOR_KEY")
    monkeypatch.setenv("BULL_ANCHOR_MASTER_KEY", collector_env.decode())
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    destination = tmp_path / "collector.key"
    runner.select_collector(
        options(collector_from_env=True), user, secret_destination=destination
    )
    assert destination.read_bytes() == collector_env


def test_conflicting_environment_aliases_block(tmp_path, collector_env, monkeypatch):
    monkeypatch.setenv(
        "BULL_ANCHOR_MASTER_KEY", "different-test-fixture-master-key-value"
    )
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="environment keys disagree"):
        runner.select_environment_collector(user, tmp_path / "collector.key")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "missing", ["BULL_REMOTE_AUDIT_ANCHOR_URL", "BULL_REMOTE_AUDIT_ANCHOR_KEY"]
)
def test_partial_environment_blocks_without_creating_a_key(
    tmp_path, collector_env, monkeypatch, missing
):
    monkeypatch.delenv(missing)
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="requires BULL_REMOTE"):
        runner.select_environment_collector(user, tmp_path / "collector.key")
    assert list(tmp_path.iterdir()) == []


def test_environment_cannot_override_explicit_inputs(tmp_path, collector_env):
    args = options(collector_from_env=True)
    args.deployment = tmp_path
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="choose --collector-from-env"):
        runner.select_collector(args, user)


def test_environment_rejects_local_url(tmp_path, collector_env, monkeypatch):
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_URL", "https://127.0.0.1/checkpoints")
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    with pytest.raises(ValueError, match="non-local"):
        runner.select_environment_collector(user, tmp_path / "collector.key")
    assert list(tmp_path.iterdir()) == []


def test_configuration_reports_paths_but_never_key_contents(tmp_path, collector_env):
    state = deployment(tmp_path, "deployment-01")
    legacy = tmp_path / ".local/share/bull-production/secrets"
    legacy.mkdir(parents=True)
    key = legacy / "cloudflare-anchor.key"
    key.write_bytes(collector_env)
    key.chmod(0o600)
    user = SimpleNamespace(pw_dir=str(tmp_path), pw_uid=os.getuid())
    report = runner.collector_configuration(user)
    assert report["deployment_paths"] == [str(state)]
    assert str(key) in report["private_key_paths"]
    assert report["environment_present"]["BULL_REMOTE_AUDIT_ANCHOR_KEY"] is True
    assert collector_env.decode().strip() not in json.dumps(report)
    assert "fixture-key-with-exact-newline" not in json.dumps(report)


def audit_fixture(run):
    # Real chain and MAC code, synthetic local receipt. Never production evidence.
    state = run / "private/deployment"
    (state / "audit").mkdir(parents=True)
    (state / "secrets").mkdir()
    master, session = b"test-master-key" * 4, "a" * 64
    runner.write_json(state / "deployment.json", {"audit_session": session})
    (state / "secrets/collector.key").write_bytes(master)
    result = {"call_id": "b" * 32, "result_sha256": "c" * 64}
    ledger = AuditLedger(state / "audit/ledger.jsonl")
    ledger.append_event("gateway_attempt", {"call_id": result["call_id"]})
    ledger.append_event(
        "gateway_result",
        {
            "call_id": result["call_id"],
            "executed": True,
            "result_digest": result["result_sha256"],
        },
    )
    check = ledger.verify()
    receipt = authenticate(
        {
            "version": 1,
            "session": session,
            "sequence": check.records,
            "head_hash": check.head_hash,
            "accepted": True,
        },
        session_key(master, session),
        purpose="acknowledgement",
    )
    runner.write_json(ledger.remote_checkpoint_path, receipt)
    return ledger, result


def test_audit_must_match_result_and_authenticated_receipt(tmp_path):
    ledger, result = audit_fixture(tmp_path)
    assert runner.verify_retained_audit(tmp_path, result)["records"] == 2
    with pytest.raises(ValueError, match="not bound"):
        runner.verify_retained_audit(tmp_path, {**result, "result_sha256": "d" * 64})
    receipt = json.loads(ledger.remote_checkpoint_path.read_text())
    runner.write_json(ledger.remote_checkpoint_path, {**receipt, "mac": "0" * 64})
    with pytest.raises(AnchorError, match="authentication failed"):
        runner.verify_retained_audit(tmp_path, result)


def test_stale_collector_receipt_cannot_qualify(tmp_path):
    ledger, result = audit_fixture(tmp_path)
    receipt = json.loads(ledger.remote_checkpoint_path.read_text())
    runner.write_json(ledger.remote_checkpoint_path, {**receipt, "sequence": 1})
    with pytest.raises(ValueError, match="did not reach"):
        runner.verify_retained_audit(tmp_path, result)


def test_exited_child_is_not_signalled_by_a_reusable_pid(monkeypatch):
    sent = []
    monkeypatch.setattr(runner.os, "killpg", lambda *args: sent.append(args))
    runner.stop_child(SimpleNamespace(pid=123, poll=lambda: 0))
    assert not sent


@pytest.mark.parametrize("failure_stage", ["permissions", "account"])
def test_failed_setup_never_deletes_an_existing_account(
    tmp_path, monkeypatch, failure_stage
):
    from tools import host_setup

    run = tmp_path / "bull-mcp-live-unit"
    run.mkdir()
    runner.write_json(
        run / "config.json",
        {"operator_uid": 1000, "source": str(runner.ROOT), "source_commit": "fixture"},
    )
    real_lstat = Path.lstat

    def metadata(path):
        if path == run:
            return SimpleNamespace(st_uid=1000, st_mode=0o40700)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runner.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(runner, "private_path", lambda path, uid: path)
    monkeypatch.setattr(
        runner.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="fixture"),
    )
    monkeypatch.setattr(runner.signal, "signal", lambda *a: None)
    monkeypatch.setattr(runner.signal, "alarm", lambda *a: None)
    monkeypatch.setattr(host_setup, "provision_cgroup", lambda user: tmp_path)
    calls = []

    def verify_runtime(*args):
        if failure_stage == "permissions":
            raise ValueError("public runtime permissions 0756, expected 0755")

    monkeypatch.setattr(runner, "verify_public_runtime", verify_runtime)

    def failed(command, *args):
        calls.append(command)
        raise OSError("account exists; fixture only")

    monkeypatch.setattr(runner, "account_command", failed)
    assert runner.root_worker(run) == 1
    assert calls == ([] if failure_stage == "permissions" else ["useradd"])
    assert json.loads((run / "report.json").read_text())["status"] == "BLOCKED"


@pytest.fixture
def private_creation_mask():
    """Use the CLI's private creation mask without leaking it to other tests."""
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.parametrize("audit_mode", ["local", "external"])
@pytest.mark.parametrize("outcome", ["pass", "gate_failure", "wrong_profile"])
def test_worker_keeps_audit_profile_through_provisioning_and_cleanup(
    tmp_path, monkeypatch, private_creation_mask, audit_mode, outcome
):
    """Exercise orchestration and real audit validation with simulated OS children.

    No account is created and no privileged process runs. This is a regression
    test for runner control flow, not live MCP, host isolation or remote evidence.
    """
    from tools import deployment_setup, host_setup
    from bulldog.local_audit import LocalAuditLedger

    run = tmp_path / "bull-mcp-live-worker-fixture"
    run.mkdir()
    (run / "project").mkdir()
    state = deployment_setup.initialize(
        run / "private/deployment", run / "project", audit_mode=audit_mode
    )
    result = {"call_id": "b" * 32, "result_sha256": "c" * 64}
    if audit_mode == "local":
        ledger = LocalAuditLedger(
            state / "audit/ledger.jsonl",
            anchor_path=state / "audit/local-checkpoint.json",
            anchor_key=(state / "secrets/local-audit.key").read_bytes(),
        )
    else:
        ledger = AuditLedger(state / "audit/ledger.jsonl", remote_anchor_url="")
    ledger.append_event("gateway_attempt", {"call_id": result["call_id"]})
    ledger.append_event(
        "gateway_result",
        {
            "call_id": result["call_id"],
            "result_digest": result["result_sha256"],
            "executed": True,
        },
    )
    if audit_mode == "external":
        checked = ledger.verify()
        session = json.loads((state / "deployment.json").read_text())["audit_session"]
        runner.write_json(
            ledger.remote_checkpoint_path,
            authenticate(
                {
                    "version": 1,
                    "session": session,
                    "sequence": checked.records,
                    "head_hash": checked.head_hash,
                    "accepted": True,
                },
                session_key((state / "secrets/collector.key").read_bytes(), session),
                purpose="acknowledgement",
            ),
        )
    runner.write_json(
        run / "config.json",
        {
            "operator_uid": 1000,
            "source": str(runner.ROOT),
            "source_commit": "fixture-only",
            "audit_mode": audit_mode,
        },
    )
    operator = SimpleNamespace(
        pw_uid=1000, pw_gid=1000, pw_name="fixture-operator", pw_dir="/nonexistent"
    )
    agent = SimpleNamespace(
        pw_uid=2000, pw_gid=2000, pw_name="fixture-agent", pw_dir="/nonexistent"
    )
    real_lstat = Path.lstat

    def metadata(path):
        if path == run:
            return SimpleNamespace(st_uid=operator.pw_uid, st_mode=0o40700)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runner.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(runner.os, "getgrouplist", lambda *a: [operator.pw_gid])
    monkeypatch.setattr(runner, "private_path", lambda path, uid: path)
    monkeypatch.setattr(runner, "verify_public_runtime", lambda *args: None)
    monkeypatch.setattr(runner.pwd, "getpwuid", lambda uid: operator)
    monkeypatch.setattr(runner.pwd, "getpwnam", lambda name: agent)
    monkeypatch.setattr(runner.grp, "getgrnam", lambda name: SimpleNamespace())
    monkeypatch.setattr(runner.signal, "signal", lambda *a: None)
    monkeypatch.setattr(runner.signal, "alarm", lambda *a: None)
    monkeypatch.setattr(host_setup, "provision_cgroup", lambda user: tmp_path)
    commands, children, stopped = [], [], []
    monkeypatch.setattr(
        runner, "account_command", lambda command, *a: commands.append(command)
    )
    monkeypatch.setattr(
        runner,
        "stop_child",
        lambda child: stopped.append(child) if child is not None else None,
    )
    monkeypatch.setattr(runner, "endpoint_ready", lambda *a: outcome != "gate_failure")

    def child_process(command, **kwargs):
        assert not any(name.startswith("BULL_") for name in kwargs["env"])
        role = command[command.index("--_role") + 1]
        if role == "agent":
            cfg = json.loads((run / "agent-config.json").read_text())
            assert cfg["audit_mode"] == audit_mode
            reported = audit_mode
            if outcome == "wrong_profile":
                reported = "external" if audit_mode == "local" else "local"
            runner.write_json(
                run / "agent/result.json",
                {
                    **result,
                    "status": runner.pass_status(reported),
                    "audit_mode": reported,
                    "checks": {"simulated_mcp_exchange": True},
                },
            )
        elif outcome == "gate_failure":
            filename = (
                "local-gates.json" if audit_mode == "local" else "production-gates.json"
            )
            runner.write_json(
                run / "private" / filename, {"failures": ["fixture host gate failed"]}
            )
        child = SimpleNamespace(
            role=role,
            poll=lambda: 1 if outcome == "gate_failure" else None,
            wait=lambda timeout: 0,
        )
        children.append(child)
        return child

    monkeypatch.setattr(runner.subprocess, "Popen", child_process)
    rc = runner.root_worker(run)
    report = json.loads((run / "report.json").read_text())
    assert report["audit_mode"] == audit_mode
    assert report["checks"]["temporary_agent_removed"] is True
    assert commands == ["useradd", "userdel", "groupdel"]
    assert all(child in stopped for child in children)
    # The real transport grants group traversal after binding the socket. This
    # simulated authority leaves the directory's initial private mode intact.
    assert (run / "endpoint").stat().st_mode & 0o777 == 0o700
    assert (run / "agent").stat().st_mode & 0o777 == 0o700
    if outcome == "gate_failure":
        assert rc == 1 and report["status"] == "BLOCKED"
        assert report["gate_failures"] == ["fixture host gate failed"]
        assert [child.role for child in children] == ["authority"]
    elif outcome == "wrong_profile":
        assert rc == 1 and report["status"] == "BLOCKED"
        assert "live client refused" in report["reason"]
        assert "audit" not in report
    else:
        assert rc == 0, report
        assert report["status"] == runner.pass_status(audit_mode)
        assert report["checks"][audit_mode + "_authority_started"] is True
        assert report["checks"][audit_mode + "_checkpoint_reached_head"] is True
        assert report["audit"]["records"] == 2
        if audit_mode == "local":
            assert report["audit"]["external_receipt"] is False
            assert "external_checkpoint_reached_head" not in report["checks"]
