"""Independent installation evidence, with no founder/service credentials."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from bulldog.anchor_service import AnchorError, AnchorStore, checkpoint, session_key
from bulldog.audit import AuditLedger
from bulldog.integrity import IntegrityViolation
from bulldog.policy_bundle import PolicyBundleError
from tools import deployment_setup as setup
from tools import host_setup


def install(tmp_path, name="alice", **kwargs):
    project = tmp_path / (name + "-project")
    project.mkdir()
    return setup.initialize(tmp_path / name, project, **kwargs)


def test_two_installations_have_independent_authority_and_no_ambient_fallback(tmp_path):
    first, second = install(tmp_path), install(tmp_path, "bob")
    a, b = setup.environment(first), setup.environment(second)
    for name in ("BULL_POLICY_BUNDLE_KEY", "BULL_INTEGRITY_MANIFEST_KEY", "BULL_REMOTE_AUDIT_ANCHOR_KEY", "BULL_AUDIT_SESSION_ID"):
        assert a[name] != b[name]
    clean = setup.isolated_environment(first, {"PATH": "/usr/bin", "BULL_REMOTE_AUDIT_ANCHOR_URL": "https://someone-else.invalid/",
                                               "BULL_APPROVAL_KEY": "/someone-else/key", "BULL_DEPLOYMENT_ASSETS": "/someone-else/images"})
    assert clean["PATH"] == "/usr/bin"
    assert "BULL_REMOTE_AUDIT_ANCHOR_URL" not in clean
    assert "BULL_APPROVAL_KEY" not in clean
    assert "BULL_DEPLOYMENT_ASSETS" not in clean
    assert clean["BULL_AUDIT_SESSION_ID"] == a["BULL_AUDIT_SESSION_ID"]


def test_installations_cannot_authenticate_to_each_others_collectors(tmp_path):
    alice, bob = install(tmp_path), install(tmp_path, "bob")
    a, b = setup.environment(alice), setup.environment(bob)
    ledger = AuditLedger(alice / "audit/fixture.jsonl")
    ledger.append_event("validation", {"purpose": "independent installation fixture"})
    record = json.loads(ledger.path.read_text().splitlines()[0])
    session = a["BULL_AUDIT_SESSION_ID"]
    frame = checkpoint(session, 1, record, session_key(a["BULL_REMOTE_AUDIT_ANCHOR_KEY"].encode(), session))
    alice_store = AnchorStore(alice / "audit/collector.sqlite", a["BULL_REMOTE_AUDIT_ANCHOR_KEY"].encode())
    bob_store = AnchorStore(bob / "audit/collector.sqlite", b["BULL_REMOTE_AUDIT_ANCHOR_KEY"].encode())
    assert alice_store.accept(frame)["accepted"] is True
    with pytest.raises(AnchorError, match="authentication"):
        bob_store.accept(frame)


@pytest.mark.parametrize("filename,error", [("policy.json", PolicyBundleError), ("integrity.json", IntegrityViolation)])
def test_cross_installation_signed_documents_are_rejected(tmp_path, filename, error):
    a, b = install(tmp_path), install(tmp_path, "bob")
    (a / filename).write_bytes((b / filename).read_bytes())
    with pytest.raises(error):
        setup.environment(a)


def test_rerun_never_rotates_keys_or_replaces_ledger(tmp_path):
    state = install(tmp_path)
    marker = state / "audit/ledger.jsonl"
    marker.write_text("existing audit state\n")
    before = {str(p.relative_to(state)): p.read_bytes() for p in state.rglob("*") if p.is_file()}
    with pytest.raises(FileExistsError):
        setup.initialize(state, tmp_path / "alice-project")
    assert before == {str(p.relative_to(state)): p.read_bytes() for p in state.rglob("*") if p.is_file()}


def test_setup_remains_private_with_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        state = install(tmp_path)
    finally:
        os.umask(old)
    for path in (state, *state.rglob("*")):
        assert path.stat().st_mode & 0o077 == 0, path
    assert len(set(p.read_bytes() for p in (state / "secrets").iterdir())) == 3


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "public"])
def test_imported_secret_requires_private_regular_file(tmp_path, mutation):
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    if mutation == "symlink":
        other = tmp_path / "alias"
        other.symlink_to(key)
        key = other
    elif mutation == "hardlink":
        os.link(key, tmp_path / "alias")
    else:
        key.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        install(tmp_path, existing_collector_key=key)
    assert not (tmp_path / "alice").exists()


def test_existing_collector_bytes_and_session_survive_configuration_changes(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32 + b"\n")
    key.chmod(0o600)
    state = install(tmp_path, existing_collector_key=key)
    before = setup.environment(state)
    setup.configure(state, url="https://operator.example/v1/checkpoints", cgroup_parent="/sys/fs/cgroup/bull-fixture")
    after = setup.environment(state)
    assert after["BULL_REMOTE_AUDIT_ANCHOR_KEY"].encode() == key.read_bytes()
    for name in ("BULL_POLICY_BUNDLE_KEY", "BULL_INTEGRITY_MANIFEST_KEY", "BULL_AUDIT_SESSION_ID"):
        assert before[name] == after[name]
    (state / "audit/ledger.jsonl").write_text("existing state")
    with pytest.raises(ValueError, match="active audit destination"):
        setup.configure(state, url="https://different.example/v1/checkpoints")


def test_private_state_cannot_be_inside_admitted_project(tmp_path):
    with pytest.raises(ValueError, match="outside"):
        setup.initialize(tmp_path / "project/state", tmp_path)
    assert not (tmp_path / "project").exists()


def test_configure_cannot_resign_changed_runtime(tmp_path, monkeypatch):
    state = install(tmp_path)
    original = (state / "deployment.json").read_bytes()
    def changed(*args, **kwargs):
        raise IntegrityViolation("changed runtime")
    monkeypatch.setattr(setup, "verify_integrity_manifest", changed)
    with pytest.raises(IntegrityViolation):
        setup.configure(state, url="https://operator.example/v1/checkpoints")
    assert (state / "deployment.json").read_bytes() == original


def test_environment_file_handles_quoted_paths_and_does_not_print_secrets(tmp_path, capsys):
    state = install(tmp_path, "quote'$(false)")
    output = state / "environment.sh"
    assert setup.main(["environment", "--state", str(state), "--output", str(output)]) == 0
    values = setup.environment(state)
    text = capsys.readouterr().out
    assert values["BULL_POLICY_BUNDLE_KEY"] not in text
    command = ['bash', '-c', 'source "$1"; "$2" -c "$3"', 'deployment-environment', str(output),
               sys.executable, 'import os; print(os.environ["BULL_POLICY_BUNDLE"])']
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    assert result.stdout.strip() == values["BULL_POLICY_BUNDLE"]
    assert output.stat().st_mode & 0o077 == 0


def test_software_approval_key_is_not_enrolled(tmp_path):
    key = tmp_path / "ordinary.pub"
    key.write_text("ssh-ed25519 AAAA software-key\n")
    from bulldog.approval_crypto import ApprovalError
    with pytest.raises(ApprovalError, match="security keys"):
        install(tmp_path, approval_public_key=key)
    assert not (tmp_path / "alice").exists()


def test_ordinary_directory_cannot_claim_cgroup_readiness(tmp_path):
    for name in ("cgroup.controllers", "cgroup.procs"):
        (tmp_path / name).write_text("")
    with pytest.raises(ValueError, match="real /sys/fs/cgroup"):
        setup.check_cgroup(tmp_path)


def test_host_provisioner_never_targets_root_service_uid(monkeypatch):
    with pytest.raises(ValueError, match="non-root"):
        host_setup.cgroup_parent(0)
    assert host_setup.cgroup_parent(1234) == Path("/sys/fs/cgroup/bull-1234")
    from types import SimpleNamespace
    import stat
    info = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_rdev=os.makedev(10, 232), st_gid=0)
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    with pytest.raises(ValueError, match="root-group"):
        host_setup.grant_kvm(SimpleNamespace(pw_uid=1234))


@pytest.mark.parametrize("capability", ["credential.read", "network.outbound", "network.post", "security_control.write"])
def test_consequential_capability_requires_enrolled_credential(tmp_path, capability):
    with pytest.raises(ValueError, match="enrolled approval"):
        install(tmp_path, capabilities=[capability])
    assert not (tmp_path / "alice").exists()


def test_source_fixture_processes_do_not_inherit_deployment_authority(tmp_path, monkeypatch):
    from tools.deployment_check import Checks
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_KEY", "private-test-marker")
    monkeypatch.setenv("BULL_AUDIT_LEDGER", "/operator/private/ledger")
    checks = Checks(tmp_path)
    command = [sys.executable, "-c", 'import os; raise SystemExit(1 if any(k.startswith("BULL_") for k in os.environ) else 0)']
    assert checks.command("isolated", command, clean_authority=True)


def test_invalid_deployment_stops_before_running_checks(tmp_path, monkeypatch):
    from tools import deployment_check
    state = install(tmp_path)
    (state / "secrets/policy.key").write_bytes(b"different-key" * 8)
    def forbidden(*args, **kwargs):
        pytest.fail("an invalid deployment must not run commands")
    monkeypatch.setattr(deployment_check.Checks, "command", forbidden)
    out = tmp_path / "report"
    assert deployment_check.main(["--deployment", str(state), "--output", str(out)]) == 1
    result = json.loads((out / "report.json").read_text())
    assert result["certified"] is False
    assert result["gates"]["deployment_configuration"]["status"] == "FAIL"


def test_partial_cgroup_configuration_removes_empty_scope(tmp_path, monkeypatch):
    from bulldog.cgroup_scope import CgroupV2Scope, CgroupUnavailable
    scope = CgroupV2Scope(tmp_path, memory_bytes=1024, processes=4, cpu_quota_us=25000)
    def unavailable(name, value):
        raise CgroupUnavailable("controller unavailable")
    monkeypatch.setattr(scope, "_write", unavailable)
    with pytest.raises(CgroupUnavailable, match="controller unavailable"):
        with scope:
            pytest.fail("partial scope must never admit a workload")
    assert list(tmp_path.iterdir()) == []
    assert scope.path is None


def test_guest_public_source_permissions_ignore_private_umask(tmp_path):
    from microvm.integration import stage_public_runtime
    source = tmp_path / "repo"
    package = source / "src/bulldog"
    package.mkdir(parents=True, mode=0o700)
    (package / "__init__.py").write_text("# public fixture\n")
    (package / "__init__.py").chmod(0o600)
    (package / "_namespace_launcher.sh").write_text("#!/bin/sh\n")
    (package / "_namespace_launcher.sh").chmod(0o600)
    (source / "microvm/guest").mkdir(parents=True)
    (source / "microvm/guest/bull-engine").write_text("#!/bin/sh\n")
    runtime = tmp_path / "runtime"
    previous = os.umask(0o077)
    try:
        stage_public_runtime(source, runtime)
    finally:
        os.umask(previous)
    assert (runtime / "src/bulldog/__init__.py").stat().st_mode & 0o777 == 0o644
    for path in (runtime / "src", runtime / "src/bulldog", runtime / "bin", runtime / "bin/bull-engine",
                 runtime / "src/bulldog/_namespace_launcher.sh"):
        assert path.stat().st_mode & 0o777 == 0o755
    assert (package / "__init__.py").stat().st_mode & 0o777 == 0o600


def test_resource_checks_refuse_root_before_starting_workloads(monkeypatch):
    from tools.cgroup_check import check_limits
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="normal operator"):
        check_limits(Path("/unused"))
