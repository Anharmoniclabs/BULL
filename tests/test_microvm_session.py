"""Adapter regressions with explicitly simulated dispatch; not KVM evidence."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from bulldog import microvm_session as session
from bulldog.models import Capability, Decision, Evaluation
from bulldog.runtime import ExecutionResult


@pytest.fixture
def paths(tmp_path):
    paths = tuple(tmp_path / name for name in ("workspace", "runtime", "outputs"))
    for path in paths:
        path.mkdir()
    (paths[1] / "workload.json").write_text(json.dumps({"version": 1, "argv": ["/usr/bin/true"], "timeout_seconds": 2}))
    return paths


@pytest.mark.parametrize("change", [
    {"argv": "echo hello"}, {"argv": []}, {"argv": ["relative"]},
    {"argv": ["/bin/echo", None]}, {"argv": ["/bin/echo", "\x00"]},
    {"timeout_seconds": True}, {"timeout_seconds": 301},
    {"granted_capabilities": ["process.exec"]}, {"version": True},
    {"provenance": "human"}, {"env": {}},
])
def test_rejects_invalid_or_authority_bearing_config(paths, change):
    spec = {"version": 1, "argv": ["/usr/bin/true"], **change}
    (paths[1] / "workload.json").write_text(json.dumps(spec))
    with pytest.raises(ValueError):
        session.load_workload(paths[1])


def test_rejects_duplicate_and_symlink_config(paths):
    config = paths[1] / "workload.json"
    config.write_text('{"version":1,"version":1,"argv":["/bin/true"]}')
    with pytest.raises(ValueError, match="duplicate"):
        session.load_workload(paths[1])
    config.unlink()
    config.symlink_to(paths[0] / "missing")
    with pytest.raises(RuntimeError):
        session.load_workload(paths[1])


def result(decision=Decision.ALLOW, code=0):
    return ExecutionResult(Evaluation(decision, 0, ()), decision == Decision.ALLOW, True,
                           decision == Decision.ESCALATE, code, "x" * 9000, "")


@pytest.mark.parametrize("decision,code,status", [
    (Decision.ALLOW, 0, "success"), (Decision.ALLOW, 1, "execution_failed"),
    (Decision.DENY, None, "policy_denied"), (Decision.ESCALATE, None, "review_required"),
])
def test_reports_bounded_result_without_overwrite(paths, monkeypatch, decision, code, status):
    calls = []
    def execute(spec, workspace):
        calls.append(spec)
        return result(decision, code)
    monkeypatch.setattr(session, "execute_workload", execute)
    assert session.run_session(*paths) == (0 if status == "success" else 1)
    summary = json.loads((paths[2] / "summary.json").read_text())
    assert summary["status"] == status
    assert summary["stdout_truncated"] and len(summary["stdout"]) == 8192
    assert list(paths[2].iterdir()) == [paths[2] / "summary.json"]
    with pytest.raises(ValueError, match="overwrite"):
        session.run_session(*paths)
    assert len(calls) == 1


def test_missing_production_configuration_does_not_dispatch(paths, monkeypatch):
    for key in list(session.os.environ):
        if key.startswith("BULL_"):
            monkeypatch.delenv(key)
    def forbidden(*args, **kwargs):
        pytest.fail("production gate bypassed")
    monkeypatch.setattr(session, "ProductionDispatcher", forbidden)
    assert session.run_session(*paths) == 1
    report = json.loads((paths[2] / "summary.json").read_text())
    assert report["status"] == "infrastructure_failure"
    assert report["executed"] is False


def test_adapter_binds_entire_argv_and_signed_ceiling(paths, monkeypatch):
    ceiling = frozenset({Capability.PROCESS_EXEC})
    runtime = SimpleNamespace(engine=SimpleNamespace(ledger=None, policy=SimpleNamespace(global_capability_ceiling=ceiling)))
    monkeypatch.setattr(session, "ProductionRuntime", lambda: runtime)
    class Dispatcher:
        def __init__(self, **kwargs):
            assert kwargs["runtime"] is runtime
            self.registry = kwargs["domain_registry"]
        def execute(self, request, command, *, project_root, timeout):
            assert request.authorized_command == tuple(command)
            assert command == ["/bin/echo", "$(touch forbidden); literal"]
            assert request.granted_capabilities == ceiling
            assert request.trusted == self.registry.trusted_context(request.domain_id)
            assert project_root == paths[0] and timeout == 2
            return result()
    monkeypatch.setattr(session, "ProductionDispatcher", Dispatcher)
    spec = session.load_workload(paths[1])
    spec["argv"] = ["/bin/echo", "$(touch forbidden); literal"]
    assert session.execute_workload(spec, paths[0]).returncode == 0


def test_timeout_is_not_replayed(paths, monkeypatch):
    calls = []
    def timeout(spec, workspace):
        calls.append(spec)
        raise subprocess.TimeoutExpired(spec["argv"], 2)
    monkeypatch.setattr(session, "execute_workload", timeout)
    assert session.run_session(*paths) == 1
    summary = json.loads((paths[2] / "summary.json").read_text())
    assert summary["status"] == "timeout" and summary["executed"] is None
    assert len(calls) == 1


def test_report_publication_does_not_overwrite_concurrent_host_file(paths, monkeypatch):
    def execute(spec, workspace):
        (paths[2] / "summary.json").write_text("host canary")
        return result()
    monkeypatch.setattr(session, "execute_workload", execute)
    with pytest.raises(FileExistsError):
        session.run_session(*paths)
    assert (paths[2] / "summary.json").read_text() == "host canary"
    assert (paths[2] / ".bull-summary.pending").exists()


def test_exception_details_are_not_exported(paths, monkeypatch):
    def unavailable(spec, workspace):
        raise RuntimeError("credential=private-value")
    monkeypatch.setattr(session, "execute_workload", unavailable)
    assert session.run_session(*paths) == 1
    text = (paths[2] / "summary.json").read_text()
    assert "private-value" not in text
    assert json.loads(text)["executed"] is None
