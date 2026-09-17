import os
from pathlib import Path

import pytest

import bulldog.snapshot as snapshot_module
from bulldog.filesystem_manifest import FilesystemManifestViolation, build_manifest
from bulldog.secure_fs import SecurePathViolation, open_beneath, trusted_root_fd
from bulldog.snapshot import SnapshotViolation, create_snapshot, destroy_snapshot
from bulldog.workspace_limits import WorkspaceBudget


def _budget(**overrides):
    values = dict(
        max_files=100,
        max_total_bytes=1024 * 1024,
        max_file_bytes=512 * 1024,
        max_depth=8,
        max_path_bytes=512,
        manifest_timeout_seconds=5.0,
        snapshot_timeout_seconds=5.0,
        malware_scan_timeout_seconds=5.0,
        snapshot_min_free_bytes=1,
    )
    values.update(overrides)
    return WorkspaceBudget(**values)


def test_file_count_budget_fails_closed(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "a").write_text("a")
    (root / "b").write_text("b")
    with pytest.raises(FilesystemManifestViolation, match="file count"):
        build_manifest(root, budget=_budget(max_files=1))


def test_total_byte_budget_fails_closed(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "a").write_bytes(b"x" * 64)
    (root / "b").write_bytes(b"y" * 64)
    with pytest.raises(FilesystemManifestViolation, match="workspace bytes"):
        build_manifest(root, budget=_budget(max_total_bytes=100, max_file_bytes=100))


def test_sparse_or_oversized_file_is_rejected_before_copy(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    huge = root / "huge.bin"
    with huge.open("wb") as fh:
        fh.truncate(1024 * 1024)
    with pytest.raises(FilesystemManifestViolation, match="file exceeds size"):
        build_manifest(root, budget=_budget(max_file_bytes=128 * 1024))


def test_directory_depth_budget_fails_closed(tmp_path):
    root = tmp_path / "workspace"
    target = root / "a" / "b" / "c"
    target.mkdir(parents=True)
    (target / "x").write_text("x")
    with pytest.raises(FilesystemManifestViolation, match="depth"):
        build_manifest(root, budget=_budget(max_depth=2))


def test_symlink_hardlink_and_fifo_are_rejected(tmp_path):
    # Symlink.
    root = tmp_path / "symlink"
    root.mkdir()
    target = root / "target"
    target.write_text("x")
    (root / "alias").symlink_to(target)
    with pytest.raises(FilesystemManifestViolation, match="symlink"):
        build_manifest(root, budget=_budget())

    # Hardlink.
    root2 = tmp_path / "hardlink"
    root2.mkdir()
    original = root2 / "original"
    original.write_text("x")
    os.link(original, root2 / "alias")
    with pytest.raises(FilesystemManifestViolation, match="hardlink"):
        build_manifest(root2, budget=_budget())

    # FIFO/special file.
    root3 = tmp_path / "fifo"
    root3.mkdir()
    os.mkfifo(root3 / "pipe")
    with pytest.raises(FilesystemManifestViolation, match="special"):
        build_manifest(root3, budget=_budget())


def test_kernel_constrained_open_refuses_symlink_component(tmp_path):
    root = tmp_path / "root"
    actual = root / "actual"
    actual.mkdir(parents=True)
    (actual / "data").write_text("safe")
    (root / "link").symlink_to(actual, target_is_directory=True)

    with trusted_root_fd(root) as root_fd:
        with pytest.raises(SecurePathViolation):
            open_beneath(root_fd, "link/data")


def test_snapshot_is_read_only_and_cleanup_restores_then_removes(tmp_path):
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "a.txt").write_text("safe")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    snapshot = create_snapshot(
        source,
        budget=_budget(),
        scratch_root=scratch,
    )
    snapshot_path = snapshot.snapshot_root
    assert snapshot_path.stat().st_mode & 0o222 == 0
    assert (snapshot_path / "a.txt").stat().st_mode & 0o222 == 0

    destroy_snapshot(snapshot)
    assert not snapshot_path.exists()
    assert list(scratch.iterdir()) == []


def test_interrupted_snapshot_cleanup_leaves_no_partial_tree(tmp_path, monkeypatch):
    source = tmp_path / "workspace"
    source.mkdir()
    (source / "a.txt").write_text("safe")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    def fail_copy(**kwargs):
        raise SnapshotViolation("synthetic interrupted copy")

    monkeypatch.setattr(snapshot_module, "_copy_file", fail_copy)
    with pytest.raises(SnapshotViolation, match="interrupted"):
        create_snapshot(
            source,
            budget=_budget(),
            scratch_root=scratch,
        )
    assert list(scratch.iterdir()) == []
