"""Setup failure must preserve source and never attest stale native binaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(TOOLS))
    spec = importlib.util.spec_from_file_location("native_builder", TOOLS / "prepare_codespace_openshell.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_docker_is_blocked_without_installing_or_creating_source(builder, tmp_path, monkeypatch):
    monkeypatch.setattr(builder.platform, "system", lambda: "Linux")
    monkeypatch.setattr(builder.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(builder.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(builder, "execute", lambda *args, **kwargs: pytest.fail("Blocked setup executed a mutation"))
    source, report = tmp_path / "source", tmp_path / "build.json"
    assert builder.build(source, report, 2) == 2
    data = json.loads(report.read_text())
    assert data["status"] == "BLOCKED" and "Docker" in data["reason"]
    assert not source.exists()


def test_read_only_check_does_not_claim_built_binaries(builder, tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "prerequisites", lambda source: [])
    monkeypatch.setattr(builder, "execute", lambda *args, **kwargs: pytest.fail("Check installed or built anything"))
    source, report = tmp_path / "source", tmp_path / "build.json"
    assert builder.build(source, report, 2, check_only=True) == 0
    data = json.loads(report.read_text())
    assert data["status"] == "READY_TO_BUILD" and "binaries" not in data
    assert not source.exists()


@pytest.mark.parametrize("dirty", [False, True])
def test_foreign_or_modified_checkout_is_preserved(builder, tmp_path, monkeypatch, dirty):
    source = tmp_path / "source"
    source.mkdir()
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Build test"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
    tracked = source / "tracked.txt"
    tracked.write_text("original\n")
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "-m", "fixture"], check=True, capture_output=True)
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if dirty:
        monkeypatch.setattr(builder, "PIN", head)
        tracked.write_text("operator edits\n")
    before = tracked.read_bytes()
    with pytest.raises(builder.PrerequisiteBlocked, match="left untouched"):
        builder.validate_source(source)
    assert tracked.read_bytes() == before
    assert builder.git(source, "rev-parse", "HEAD") == head


def test_static_validation_failure_cannot_attest_leftover_binaries(builder, tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for name in builder.BINARIES:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stale binary")
        path.chmod(0o755)
    monkeypatch.setattr(builder, "prerequisites", lambda source: [])
    monkeypatch.setattr(builder, "validate_source", lambda source: None)
    monkeypatch.setattr(builder.shutil, "which", lambda name, **kwargs: "/usr/bin/" + name)
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        if any("verify-static-binary.sh" in str(arg) for arg in command):
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(builder, "execute", execute)
    report = tmp_path / "build.json"
    assert builder.build(source, report, 2) == 1
    data = json.loads(report.read_text())
    assert data["status"] == "FAIL" and "binaries" not in data
    assert not any("--help" in call for call in calls)
    assert all((source / name).read_text() == "stale binary" for name in builder.BINARIES)


def test_shell_withholds_native_tests_after_failed_build_even_if_preflight_passes(tmp_path):
    # Controlled phase failure: no dependencies, Rust builds, or Docker are run.
    wrapper = tmp_path / "bin"
    wrapper.mkdir()
    shim = wrapper / "python3"
    # Use an absolute interpreter to avoid recursing through PATH.
    shim.write_text("#!" + sys.executable + "\n" + '''
import json, os, pathlib, sys
a = sys.argv[1:]
if a[:2] == ["-m", "venv"]:
    p = pathlib.Path(a[2]) / "bin/python"
    p.parent.mkdir(parents=True)
    p.symlink_to(__file__)
    sys.exit(0)
if a[:2] == ["-m", "pip"]:
    sys.exit(0)
if a[:2] == ["-m", "pytest"]:
    pathlib.Path(next(x.split("=", 1)[1] for x in a if x.startswith("--junitxml="))).write_text('<testsuite><testcase/></testsuite>')
    sys.exit(0)
if a and a[0].endswith("qualify_openshell_operational.py"):
    out = pathlib.Path(a[a.index("--output") + 1]); out.mkdir()
    (out / "report.json").write_text(json.dumps({"faults": {"passed": True, "cases": [{"pass": True}]}, "concurrency": {"requests": 10000, "effects": 10000, "correlation": {"exact": True}, "ledger_verification": {"valid": True}}}))
    sys.exit(0)
if a and a[0].endswith("prepare_codespace_openshell.py"):
    pathlib.Path(a[a.index("--report") + 1]).write_text(json.dumps({"status": "FAIL", "reason": "injected build failure"}))
    sys.exit(1)
if a and a[0].endswith("openshell_qualification_results.py") and "preflight" in a:
    out = pathlib.Path(a[a.index("--output") + 1])
    (out / "native-preflight.json").write_text(json.dumps({"status": "READY", "missing": []}))
    sys.exit(0)
if a and a[0].endswith(("qualify_openshell_native_faults.py", "openshell_experiment.py")):
    sys.exit("Native phase must not run with stale binaries")
os.execv(''' + repr(sys.executable) + ''', [''' + repr(sys.executable) + ''', *a])
''')
    shim.chmod(0o755)
    output = tmp_path / "results"
    done = subprocess.run(["bash", str(TOOLS / "run_codespace_openshell_operational.sh"),
                           "--output", str(output), "--quick", "--prepare-openshell", "--os-src", str(tmp_path / "native")],
                          cwd=tmp_path, env={**os.environ, "PATH": str(wrapper) + os.pathsep + os.environ["PATH"]},
                          capture_output=True, text=True, timeout=30)
    assert done.returncode == 1
    summary = json.loads((output / "summary.json").read_text())
    assert summary["exit_codes"]["setup-native"] == 1
    assert "native_faults" not in summary["exit_codes"] and "native_composition" not in summary["exit_codes"]
    assert "Native tests withheld" in done.stdout
    assert summary["status"] == "FAIL"
