"""Reporting must not turn missing evidence into PASS or publish runtime secrets."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

SPEC = importlib.util.spec_from_file_location(
    "qualification_results", Path(__file__).resolve().parents[1] / "tools/openshell_qualification_results.py")
results = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(results)


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "-b", "operator-work")
    git(root, "config", "user.name", "Qualification test")
    git(root, "config", "user.email", "test@example.invalid")
    (root / "source.txt").write_text("qualified source\n")
    git(root, "add", "source.txt")
    git(root, "commit", "-m", "source")
    return root


def evidence(tmp_path, checkout, quick=False):
    out = tmp_path / "evidence"
    out.mkdir()
    results.initialize(checkout, out, quick)
    (out / "stage-exit-codes.tsv").write_text(
        "setup-venv\t0\nsetup-install\t0\nregression\t0\nloopback\t0\nnative-preflight\t2\n")
    (out / "regression.xml").write_text('<testsuites><testsuite><testcase name="a"/><testcase name="skip"><skipped/></testcase></testsuite></testsuites>')
    (out / "loopback").mkdir()
    results.write_json(out / "loopback/report.json", {
        "faults": {"passed": True, "cases": [{"pass": True}]},
        "concurrency": {"requests": 10000, "effects": 10000, "correlation": {"exact": True},
                        "ledger_verification": {"valid": True}},
        "scaling": {"final_verification": {"valid": True, "records": 1000000}}})
    results.write_json(out / "native-preflight.json", {"status": "BLOCKED", "missing": ["docker"]})
    return out


def checks(out):
    return {r["check"]: r for r in results.read_json(out / "summary.json")["checks"]}


def test_blocked_native_retains_passed_local_tests_and_open_boundaries(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    assert results.finalize(out, 0) == 2
    rows = checks(out)
    assert rows["Full regression"]["status"] == "PASS"
    assert rows["Native faults/restart/revocation"]["status"] == "BLOCKED"
    assert rows["Native OCSF identity export"]["status"] == "OPEN"
    assert results.read_json(out / "summary.json")["regression_counts"] == {"passed": 1, "failed": 0, "skipped": 1}
    assert (out / "SUMMARY.md").is_file() and (out / "summary.csv").is_file()


@pytest.mark.parametrize("missing", ["regression.xml", "loopback/report.json"])
def test_success_exit_without_evidence_never_passes(tmp_path, checkout, missing):
    out = evidence(tmp_path, checkout)
    (out / missing).unlink()
    assert results.finalize(out, 0) == 1
    assert results.read_json(out / "summary.json")["status"] == "FAIL"


def test_quick_does_not_claim_scaling_pass(tmp_path, checkout):
    out = evidence(tmp_path, checkout, quick=True)
    assert results.finalize(out, 0) == 2
    assert checks(out)["Million-record audit scaling"]["status"] == "NOT_RUN"


def test_setup_failure_is_reported_without_installation(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    (out / "stage-exit-codes.tsv").write_text("setup-venv\t0\nsetup-install\t1\n")
    assert results.finalize(out, 1) == 1
    assert checks(out)["Python/dependencies"]["status"] == "FAIL"
    assert checks(out)["Full regression"]["status"] == "NOT_RUN"


def test_regression_xml_failure_overrides_zero_exit(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    (out / "regression.xml").write_text('<testsuite><testcase><failure/></testcase></testsuite>')
    assert results.finalize(out, 0) == 1
    assert checks(out)["Full regression"]["status"] == "FAIL"


def test_export_allowlist_excludes_keys_logs_state_and_symlinks(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    results.finalize(out, 0)
    for name in ("audit.key", "policy.key", "credentials.sqlite", "terminal.log", "gateway.toml"):
        (out / name).write_text("PRIVATE-CONTENT")
    (out / "loopback/exact-correlation.json").symlink_to(out / "audit.key")
    (out / "composition").mkdir()
    results.write_json(out / "composition/results.json", {"results": [{"pass": True}], "meta": {"secret": "PRIVATE-CONTENT"}})
    target = tmp_path / "export"
    results.export_evidence(out, target)
    assert "PRIVATE-CONTENT" not in "".join(p.read_text() for p in target.rglob("*") if p.is_file())
    assert not (target / "loopback/exact-correlation.json").exists()
    assert "meta" not in results.read_json(target / "composition/results.json")


def test_large_correlation_export_is_compact_and_preserves_count(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    results.write_json(out / "loopback/exact-correlation.json", {
        "rows": [{"request_id": "x" * 300} for _ in range(10000)], "summary": {"exact": True}})
    results.finalize(out, 0)
    target = tmp_path / "export"
    results.export_evidence(out, target)
    path = target / "loopback/exact-correlation.json"
    assert path.stat().st_size < 1000
    assert results.read_json(path)["row_count"] == 10000
    assert results.read_json(path)["summary"]["exact"] is True
    hashes = results.read_json(target / "local-evidence-manifest.json")["files"]
    assert any(p["path"] == "loopback/exact-correlation.json" and p["bytes"] > 2_000_000 for p in hashes)


def test_shell_runner_from_unrelated_directory_finalizes_setup_failure(tmp_path):
    wrapper = tmp_path / "bin"
    wrapper.mkdir()
    (wrapper / "python3").write_text(
        '#!/bin/bash\nif [[ "$1" == -m && "$2" == venv ]]; then echo "forced venv failure"; exit 7; fi\n'
        + "exec " + shlex.quote(sys.executable) + ' "$@"\n')
    (wrapper / "python3").chmod(0o755)
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "results"
    env = {**os.environ, "PATH": str(wrapper) + os.pathsep + os.environ["PATH"]}
    done = subprocess.run(["bash", str(root / "tools/run_codespace_openshell_operational.sh"),
                           "--output", str(output)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode == 1
    assert "| Python/dependencies | FAIL |" in done.stdout
    assert "forced venv failure" in (output / "terminal.log").read_text()
    assert results.read_json(output / "summary.json")["exit_codes"]["setup-venv"] == 7
    again = subprocess.run(["bash", str(root / "tools/run_codespace_openshell_operational.sh"),
                            "--output", str(output)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert again.returncode == 2
    assert "Output already exists" in again.stderr


def local_remote(tmp_path, checkout):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    url = "https://github.com/Anharmoniclabs/BULL.git"
    git(checkout, "remote", "add", "origin", url)
    git(checkout, "config", "url." + str(remote) + ".insteadOf", url)
    # get-url expands insteadOf; the policy checks the configured URL instead.
    return remote


def test_actual_evidence_commit_and_push_preserve_operator_branch(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    remote = local_remote(tmp_path, checkout)
    before = git(checkout, "rev-parse", "HEAD")
    results.finalize(out, 0)
    assert results.publish(checkout, out) == 0
    publication = results.read_json(out / "publication.json")
    assert publication["status"] == "PUSHED"
    assert git(remote, "rev-parse", "refs/heads/" + publication["branch"]) == publication["commit"]
    assert git(checkout, "branch", "--show-current") == "operator-work"
    assert git(checkout, "rev-parse", "HEAD") == before
    assert not git(checkout, "status", "--porcelain")
    changed = git(remote, "diff-tree", "--no-commit-id", "--name-only", "-r", publication["commit"]).splitlines()
    assert changed and all(p.startswith("docs/evidence/codespaces/") for p in changed)


def test_dirty_source_cannot_publish_misbound_evidence(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    results.finalize(out, 0)
    (checkout / "source.txt").write_text("operator edits\n")
    with pytest.raises(ValueError, match="changed"):
        results.publish(checkout, out)
    assert (checkout / "source.txt").read_text() == "operator edits\n"


def test_failed_push_retains_committed_evidence_for_retry(tmp_path, checkout):
    out = evidence(tmp_path, checkout)
    remote = local_remote(tmp_path, checkout)
    hook = remote / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    results.finalize(out, 0)
    with pytest.raises(subprocess.CalledProcessError):
        results.publish(checkout, out)
    publication = results.read_json(out / "publication.json")
    work = Path(publication["worktree"])
    assert publication["status"] == "PUBLISH_FAILED"
    assert git(work, "rev-parse", "HEAD") == publication["commit"]
    assert git(checkout, "branch", "--show-current") == "operator-work"
    git(checkout, "worktree", "remove", str(work))
