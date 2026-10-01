"""Real file-permission checks; these do not qualify a separate-UID MCP session."""

import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

from tools import run_codespace_agent_gateway as runner


@pytest.mark.parametrize("isolated", [False, True])
def test_fresh_helper_imports_do_not_write_to_verified_source(tmp_path, isolated):
    """Run real cold imports, including -I which ignores PYTHON* environment.

    No provisioning or account changes occur in this subprocess.
    """
    source = tmp_path / "source"
    (source / "tools").mkdir(parents=True)
    for name in ("run_codespace_agent_gateway.py", "host_setup.py"):
        shutil.copyfile(runner.ROOT / "tools" / name, source / "tools" / name)
    script = source / "tools/run_codespace_agent_gateway.py"
    before = {
        path.relative_to(source): path.read_bytes() for path in source.rglob("*.py")
    }
    command = [
        "/usr/bin/python3",
        *(["-I"] if isolated else []),
        "-c",
        """
import runpy, sys
runpy.run_path(sys.argv[1])
from tools import host_setup
assert callable(host_setup.provision_cgroup)
assert sys.dont_write_bytecode
""",
        str(script),
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stderr
    after = {
        path.relative_to(source): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert not list(source.rglob("__pycache__"))


@pytest.fixture
def installation(tmp_path):
    run = tmp_path / "bull-mcp-live-public-fixture"
    run.mkdir(mode=0o700)
    private = run / "private"
    private.mkdir(mode=0o700)
    key = private / "fixture.key"
    key.write_bytes(b"private fixture bytes, never a real key")
    key.chmod(0o600)
    for name in ("source/src", "venv/bin", "venv/lib"):
        (run / name).mkdir(parents=True)
    (run / "source/src/module.py").write_text("VALUE = 1\n")
    (run / "venv/lib64").symlink_to("lib", target_is_directory=True)
    for name in ("python", "bull-mcp"):
        path = run / "venv/bin" / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    return run


def private_snapshot(run):
    paths = [run / "private", run / "private/fixture.key"]
    snapshot = []
    for path in paths:
        info = path.stat()
        snapshot.append(
            (
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_nlink,
                path.read_bytes() if path.is_file() else None,
            )
        )
    return snapshot


@pytest.mark.parametrize("directory_mode", [0o756, 0o700, 0o777])
def test_fresh_runtime_becomes_readable_but_not_writable_to_other_uids(
    installation, directory_mode
):
    run = installation
    for name in ("source", "venv"):
        root = run / name
        for path in (root, *root.rglob("*")):
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(directory_mode)
            elif path.name in {"python", "bull-mcp"}:
                path.chmod(0o6755)  # Also strip setuid/setgid from copied executables.
            else:
                path.chmod(0o666)
    before = private_snapshot(run)
    runner.prepare_public_runtime(run)
    runner.verify_public_runtime(run, os.geteuid())
    assert stat.S_IMODE(run.stat().st_mode) == 0o711
    assert stat.S_IMODE((run / "venv/bin").stat().st_mode) == 0o755
    assert stat.S_IMODE((run / "venv/bin/python").stat().st_mode) == 0o755
    assert stat.S_IMODE((run / "source/src/module.py").stat().st_mode) == 0o644
    assert (run / "venv/lib64").is_symlink()
    assert private_snapshot(run) == before


@pytest.mark.parametrize("target", ["venv/bin", "source/src/module.py"])
def test_permission_regression_is_rejected_without_repair(installation, target):
    runner.prepare_public_runtime(installation)
    path = installation / target
    mode = 0o756 if path.is_dir() else 0o666
    path.chmod(mode)
    with pytest.raises(ValueError, match="public runtime permissions"):
        runner.verify_public_runtime(installation, os.geteuid())
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_foreign_owned_cache_is_still_rejected(installation, monkeypatch):
    """Simulate a different owner without changing real file ownership."""
    cache = installation / "source/tools/__pycache__/unexpected.pyc"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"untrusted cache fixture")
    runner.prepare_public_runtime(installation)
    lstat = Path.lstat

    def metadata(path):
        info = lstat(path)
        if path == cache:
            values = list(info)
            values[4] = 0 if os.geteuid() != 0 else 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(ValueError, match="foreign owner"):
        runner.verify_public_runtime(installation, os.geteuid())
    assert cache.read_bytes() == b"untrusted cache fixture"


@pytest.mark.parametrize("kind", ["file_link", "directory_link", "hardlink", "fifo"])
def test_unexpected_entries_cannot_expose_or_change_private_evidence(
    installation, kind
):
    run = installation
    public = run / "venv/lib/unexpected"
    private = run / "private/fixture.key"
    if kind == "file_link":
        public.symlink_to(private)
    elif kind == "directory_link":
        public.symlink_to(run / "private", target_is_directory=True)
    elif kind == "hardlink":
        os.link(private, public)
    else:
        os.mkfifo(public, 0o600)
    (run / "source").chmod(0o756)
    before = private_snapshot(run)
    with pytest.raises(ValueError, match="public runtime"):
        runner.prepare_public_runtime(run)
    assert stat.S_IMODE(run.stat().st_mode) == 0o700
    assert stat.S_IMODE((run / "source").stat().st_mode) == 0o756
    assert private_snapshot(run) == before


def test_symlinked_installation_root_is_rejected(installation):
    root = installation / "source"
    root.rename(installation / "original-source")
    root.symlink_to(installation / "original-source", target_is_directory=True)
    with pytest.raises(ValueError, match="real directory"):
        runner.prepare_public_runtime(installation)
    assert stat.S_IMODE(installation.stat().st_mode) == 0o700


def test_failed_chmod_keeps_parent_private(installation, monkeypatch):
    path = installation / "venv/bin"
    path.chmod(0o756)
    chmod = runner.os.chmod

    def ineffective_chmod(target, mode, **kwargs):
        if Path(target) != path:
            chmod(target, mode, **kwargs)

    monkeypatch.setattr(runner.os, "chmod", ineffective_chmod)
    with pytest.raises(ValueError, match="0756, expected 0755"):
        runner.prepare_public_runtime(installation)
    assert stat.S_IMODE(installation.stat().st_mode) == 0o700


def test_nonexecutable_python_cannot_be_published(installation):
    (installation / "venv/bin/python").chmod(0o644)
    with pytest.raises(ValueError, match="entry point"):
        runner.prepare_public_runtime(installation)
    assert stat.S_IMODE(installation.stat().st_mode) == 0o700


def test_real_venv_and_bridge_execute_after_directory_repair(tmp_path):
    """Create real Python files, recreate 0756, then execute a fixture bridge.

    Runs under the current UID; no MCP authority or separate-account proof.
    """
    run = tmp_path / "bull-mcp-live-real-python"
    run.mkdir(mode=0o700)
    (run / "private").mkdir(mode=0o700)
    (run / "source").mkdir()
    subprocess.run(
        [
            "/usr/bin/python3",
            "-m",
            "venv",
            "--without-pip",
            "--copies",
            str(run / "venv"),
        ],
        check=True,
        capture_output=True,
        timeout=30,
        umask=0o022,
    )
    python = run / "venv/bin/python"
    bridge = run / "venv/bin/bull-mcp"
    bridge.write_text(f"#!{python}\nprint('fixture bridge executed')\n")
    bridge.chmod(0o755)
    for path in (run / "venv", run / "venv/bin"):
        path.chmod(0o756)
    runner.prepare_public_runtime(run)
    runner.verify_public_runtime(run, os.geteuid())
    for command, expected in (
        (
            [str(python), "-I", "-c", "print('fixture Python executed')"],
            "fixture Python executed",
        ),
        ([str(bridge)], "fixture bridge executed"),
    ):
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=10
        )
        assert result.stdout.strip() == expected
