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


def test_failed_account_creation_never_deletes_an_existing_account(
    tmp_path, monkeypatch
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

    def failed(command, *args):
        calls.append(command)
        raise OSError("account exists; fixture only")

    monkeypatch.setattr(runner, "account_command", failed)
    assert runner.root_worker(run) == 1
    assert calls == ["useradd"]
    assert json.loads((run / "report.json").read_text())["status"] == "BLOCKED"
