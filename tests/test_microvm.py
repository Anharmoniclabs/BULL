"""Host-only regressions; these tests do not claim a hardware boot."""
import os
import hashlib
from pathlib import Path
import signal
import shutil
import subprocess
import sys

import pytest

from bulldog import microvm


def test_shipped_defaults_parse(tmp_path):
    # Checkout permissions are environment-dependent. Provision the template as
    # an owner-controlled deployment file before exercising the real loader.
    template = Path(__file__).resolve().parents[1] / "microvm/config/defaults.env"
    config = tmp_path / "deployment.env"
    config.write_bytes(template.read_bytes())
    config.chmod(0o600)
    values = microvm.config_file(config)
    assert values["DEV_9P"] == "false"
    assert values["CPUS"] == "2"


def test_amd_native_profile_requires_supported_vendor_and_feature(monkeypatch):
    monkeypatch.setattr(Path, 'read_text', lambda self: 'vendor_id : AuthenticAMD\nflags : ssbd\n')
    assert microvm.cpu_argument('amd-native-ssbd') == 'host,ssbd=off,amd-ssbd=on,enforce'
    monkeypatch.setattr(Path, 'read_text', lambda self: 'vendor_id : GenuineIntel\nflags : ssbd\n')
    with pytest.raises(microvm.MicroVMError, match='AMD host'):
        microvm.cpu_argument('amd-native-ssbd')
    with pytest.raises(microvm.MicroVMError, match='unsupported'):
        microvm.cpu_argument('host,mitigations=off')


def test_pinned_firmware_rejects_changes_and_symlinks(tmp_path):
    firmware = tmp_path / "qboot.rom"
    firmware.write_bytes(b"fixture")
    firmware.chmod(0o600)
    values = {"FIRMWARE": str(firmware), "FIRMWARE_SHA256": hashlib.sha256(b"fixture").hexdigest()}
    assert microvm.firmware_bytes(values) == b"fixture"
    firmware.write_bytes(b"changed")
    with pytest.raises(microvm.MicroVMError, match="SHA-256"):
        microvm.firmware_bytes(values)
    alias = tmp_path / "alias"
    alias.symlink_to(firmware)
    values["FIRMWARE"] = str(alias)
    with pytest.raises((OSError, RuntimeError)):
        microvm.firmware_bytes(values)


@pytest.mark.parametrize(("line", "reason"), [
    ("BULL_MICROVM_CPUS=$(touch /tmp/no)", "invalid literal"),
    ("BULL_MICROVM_CPUS='2'", "invalid literal"),
    ("BULL_MICROVM_NOPE=2", "unknown configuration key"),
    ("export BULL_MICROVM_CPUS=2", "invalid literal"),
    ("BULL_MICROVM_CPUS=2\nBULL_MICROVM_CPUS=3", "duplicate configuration key"),
    ("BULL_MICROVM_CPUS=2 # comment", "invalid literal"),
])
def test_config_rejects_nonliteral_unknown_duplicate(tmp_path, line, reason):
    config = tmp_path / "deployment.env"
    config.write_text(line)
    config.chmod(0o600)
    with pytest.raises(microvm.MicroVMError, match=reason):
        microvm.config_file(config)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_config_rejects_writable_permissions(tmp_path, mode):
    config = tmp_path / "deployment.env"
    config.write_text("BULL_MICROVM_CPUS=2\n")
    config.chmod(0o600)
    assert microvm.config_file(config)["CPUS"] == "2"
    config.chmod(mode)
    with pytest.raises(microvm.MicroVMError, match="not group/world writable"):
        microvm.config_file(config)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_firmware_rejects_writable_permissions(tmp_path, mode):
    firmware = tmp_path / "qboot.rom"
    firmware.write_bytes(b"fixture")
    firmware.chmod(0o600)
    values = {"FIRMWARE": str(firmware), "FIRMWARE_SHA256": hashlib.sha256(b"fixture").hexdigest()}
    assert microvm.firmware_bytes(values) == b"fixture"
    firmware.chmod(mode)
    with pytest.raises(microvm.MicroVMError, match="owner-controlled regular file"):
        microvm.firmware_bytes(values)


@pytest.mark.parametrize("raw", ["/", "/tmp", "/home", str(Path.home()), "/etc", "/usr/bin"])
def test_broad_roots_rejected(raw):
    with pytest.raises(microvm.MicroVMError):
        microvm.restricted_root(raw)


def test_alias_overlap_and_approvals(tmp_path):
    workspace = tmp_path / "project"
    workspace.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(workspace)
    trusted = {"APPROVED_WORKSPACE_ROOT": str(workspace), "APPROVED_RUNTIME_ROOT": str(workspace)}
    with pytest.raises(microvm.MicroVMError, match="overlap"):
        microvm.roots({"WORKSPACE": str(workspace), "RUNTIME_DIR": str(alias)}, trusted)
    with pytest.raises(microvm.MicroVMError, match="configuration"):
        microvm.roots({"WORKSPACE": str(workspace), "RUNTIME_DIR": str(alias)}, {})
    child = workspace / "child"
    child.mkdir()
    assert microvm.overlap(workspace, child)
    assert microvm.overlap(child, workspace)


def test_engine_parent_symlink_rejected(tmp_path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "real").mkdir()
    engine = runtime / "real/engine"
    engine.write_text("#!/bin/sh\n")
    engine.chmod(0o755)
    (runtime / "bin").symlink_to(runtime / "real")
    with pytest.raises(RuntimeError):
        microvm.engine_path(runtime, "/bull_runtime/bin/engine")
    microvm.engine_path(runtime, "/bull_runtime/real/engine")


@pytest.mark.parametrize("value", ["0", "-1", "nan", "1.5", "9" * 50, "65537"])
def test_numeric_bounds(value):
    with pytest.raises(microvm.MicroVMError):
        microvm.bounded(value, "memory", 4096, 65536)


def fixture_values(tmp_path):
    for name in ("workspace", "runtime", "rootfs"):
        (tmp_path / name).mkdir()
    (tmp_path / "runtime/bin").mkdir()
    engine = tmp_path / "runtime/bin/bull-engine"
    engine.write_text("#!/bin/sh\nexit 0\n")
    engine.chmod(0o755)
    (tmp_path / "kernel").write_bytes(b"test kernel")
    (tmp_path / "qboot.rom").write_bytes(b"test firmware")
    (tmp_path / "qboot.rom").chmod(0o600)
    config = tmp_path / "deployment.env"
    config.write_text("\n".join([
        f"BULL_MICROVM_APPROVED_WORKSPACE_ROOT={tmp_path / 'workspace'}",
        f"BULL_MICROVM_APPROVED_RUNTIME_ROOT={tmp_path / 'runtime'}",
        f"BULL_MICROVM_WORKSPACE={tmp_path / 'workspace'}",
        f"BULL_MICROVM_RUNTIME_DIR={tmp_path / 'runtime'}",
        f"BULL_MICROVM_KERNEL={tmp_path / 'kernel'}",
        f"BULL_MICROVM_ROOTFS={tmp_path / 'rootfs'}",
        "BULL_MICROVM_CPUS=2",
        f"BULL_MICROVM_FIRMWARE={tmp_path / 'qboot.rom'}",
        f"BULL_MICROVM_FIRMWARE_SHA256={hashlib.sha256(b'test firmware').hexdigest()}",
    ]))
    config.chmod(0o600)
    return config


def test_diagnostic_is_side_effect_free_and_precedence(tmp_path, monkeypatch, capsys):
    config = fixture_values(tmp_path)
    monkeypatch.setenv("BULL_MICROVM_CPUS", "3")
    # Firmware authority must remain in the trusted file, not the environment.
    monkeypatch.setenv("BULL_MICROVM_FIRMWARE", "/untrusted/firmware")
    monkeypatch.setenv("BULL_MICROVM_FIRMWARE_SHA256", "0" * 64)
    def forbidden(*args, **kwargs):
        pytest.fail("diagnostic performed a side effect")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(microvm.tempfile, "TemporaryDirectory", forbidden)
    assert microvm.main(["--config", str(config), "--print-command"]) == 0
    assert "-smp 3" in capsys.readouterr().out
    assert microvm.main(["--config", str(config), "--cpus", "4", "--print-command"]) == 0
    assert "-smp 4" in capsys.readouterr().out


def test_images_are_default_and_no_network(tmp_path):
    values = dict(microvm.DEFAULTS, KERNEL="/kernel", ROOTFS="/rootfs.ext4")
    command = microvm.qemu_command(values, tmp_path / "workspace", tmp_path / "runtime", tmp_path)
    assert "-fsdev" not in command
    assert command.count("virtio-blk-device,drive=workspace") == 1
    assert command[command.index("-net") + 1] == "none"
    assert sum("readonly=on" in part for part in command) == 3
    assert command[command.index("-M") + 1] == microvm.MACHINE
    assert command[command.index("-bios") + 1] == str(tmp_path / "qboot.rom")


def test_image_rejects_existing_and_parent_symlink(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "output"
    destination.mkdir(mode=0o700)
    existing = destination / "image"
    existing.symlink_to(tmp_path / "missing")
    with pytest.raises(microvm.MicroVMError, match="exists"):
        microvm.build_image(source, existing)
    alias = tmp_path / "alias"
    alias.symlink_to(destination)
    with pytest.raises(RuntimeError):
        microvm.build_image(source, alias / "new")


def test_interrupted_build_leaves_no_output_or_scratch(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_text("hello")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    def interrupted(*args, **kwargs):
        raise subprocess.TimeoutExpired("mkfs", 120)
    monkeypatch.setattr(microvm, "supervise", interrupted)
    with pytest.raises(subprocess.TimeoutExpired):
        microvm.build_image(source, output / "image")
    assert list(output.iterdir()) == []
    assert (source / "file").read_text() == "hello"


def test_supervisor_reaps_exact_child_on_timeout(tmp_path):
    pidfile = tmp_path / "pid"
    code = "import os,time,pathlib; pathlib.Path(%r).write_text(str(os.getpid())); time.sleep(30)" % str(pidfile)
    with pytest.raises(microvm.MicroVMError, match="lifetime"):
        microvm.supervise([sys.executable, "-c", code], 1)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


@pytest.mark.skipif(not shutil.which("mkfs.ext4") or not shutil.which("debugfs"), reason="e2fsprogs required")
def test_real_image_contains_mountpoints_and_does_not_overwrite(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "canary").write_text("original")
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    init = tmp_path / "init"
    init.write_text("#!/bin/sh\n")
    image = output / "root.ext4"
    microvm.build_image(source, image, init=init)
    for entry in ("workspace", "bull_runtime", "dev", "proc", "sys", "run", "tmp", "sbin/bull-init"):
        result = subprocess.run(["debugfs", "-R", "stat /" + entry, str(image)], capture_output=True, text=True, check=True)
        assert "Inode:" in result.stdout
    assert image.stat().st_mode & 0o777 == 0o444
    assert (source / "canary").read_text() == "original"
    assert not (source / "sbin").exists()
    before = image.stat()
    with pytest.raises(microvm.MicroVMError, match="exists"):
        microvm.build_image(source, image, init=init)
    assert image.stat().st_ino == before.st_ino
