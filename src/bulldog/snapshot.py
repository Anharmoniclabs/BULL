from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import tempfile

from .filesystem_manifest import (
    FilesystemManifest,
    FilesystemManifestViolation,
    ManifestEntry,
    build_manifest,
)
from .secure_fs import SecurePathViolation, open_beneath, trusted_root_fd
from .workspace_limits import (
    WorkspaceBudget,
    WorkspaceLimitViolation,
    deadline_after,
    require_before,
)


class SnapshotViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class ProjectSnapshot:
    source_root: Path
    snapshot_root: Path
    source_hash: str
    snapshot_hash: str


def _content_hash(manifest: FilesystemManifest) -> str:
    digest = hashlib.sha256()
    for entry in manifest.entries:
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry.kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry.size).encode("ascii"))
        digest.update(b"\0")
        if entry.sha256 is not None:
            digest.update(entry.sha256.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _identity_index(manifest: FilesystemManifest) -> tuple[tuple, ...]:
    return tuple(
        (
            entry.path,
            entry.kind,
            entry.device,
            entry.inode,
            entry.size,
            entry.sha256,
        )
        for entry in manifest.entries
    )


def hash_tree(
    root: str | Path,
    *,
    budget: WorkspaceBudget | None = None,
) -> str:
    try:
        manifest = build_manifest(root, budget=budget)
    except FilesystemManifestViolation as exc:
        raise SnapshotViolation(str(exc)) from exc
    return _content_hash(manifest)


def _copy_file(
    *,
    source_root_fd: int,
    entry: ManifestEntry,
    destination: Path,
    deadline: float,
) -> None:
    try:
        source_fd = open_beneath(
            source_root_fd,
            entry.path,
            flags=os.O_RDONLY,
        )
    except SecurePathViolation as exc:
        raise SnapshotViolation(str(exc)) from exc

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination_fd = None
    digest = hashlib.sha256()
    copied = 0
    try:
        source_stat = os.fstat(source_fd)
        if (
            source_stat.st_dev != entry.device
            or source_stat.st_ino != entry.inode
            or source_stat.st_size != entry.size
            or source_stat.st_nlink != 1
        ):
            raise SnapshotViolation(
                f"source changed before snapshot copy: {entry.path}"
            )

        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        while True:
            try:
                require_before(deadline, "workspace snapshot")
            except WorkspaceLimitViolation as exc:
                raise SnapshotViolation(str(exc)) from exc
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            copied += len(block)
            if copied > entry.size:
                raise SnapshotViolation(
                    f"source grew while snapshotting: {entry.path}"
                )
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]

        if copied != entry.size or digest.hexdigest() != entry.sha256:
            raise SnapshotViolation(
                f"source changed while snapshotting: {entry.path}"
            )
        after = os.fstat(source_fd)
        if (
            after.st_dev != entry.device
            or after.st_ino != entry.inode
            or after.st_size != entry.size
        ):
            raise SnapshotViolation(
                f"source changed after snapshot copy: {entry.path}"
            )
        os.fsync(destination_fd)
        readonly_mode = 0o444 | (entry.mode & 0o111)
        os.fchmod(destination_fd, readonly_mode)
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def create_snapshot(
    source_root: str | Path,
    *,
    budget: WorkspaceBudget | None = None,
    scratch_root: str | Path | None = None,
) -> ProjectSnapshot:
    """Create a bounded immutable snapshot from a kernel-constrained manifest."""

    budget = budget or WorkspaceBudget()
    try:
        budget.validate()
    except WorkspaceLimitViolation as exc:
        raise SnapshotViolation(str(exc)) from exc

    source_root = Path(source_root).resolve(strict=True)
    snapshot_deadline = deadline_after(budget.snapshot_timeout_seconds)

    try:
        source_before = build_manifest(
            source_root,
            budget=budget,
            deadline=snapshot_deadline,
        )
    except FilesystemManifestViolation as exc:
        raise SnapshotViolation(str(exc)) from exc

    scratch = Path(
        scratch_root
        if scratch_root is not None
        else os.environ.get("BULL_SNAPSHOT_ROOT", "/tmp")
    ).resolve(strict=True)
    if not scratch.is_dir():
        raise SnapshotViolation("snapshot scratch root is not a directory")

    usage = shutil.disk_usage(scratch)
    required_free = source_before.total_bytes + budget.snapshot_min_free_bytes
    if usage.free < required_free:
        raise SnapshotViolation(
            "snapshot scratch filesystem lacks required free-space reserve"
        )

    snapshot_parent = Path(
        tempfile.mkdtemp(prefix="bull_snapshot_", dir=str(scratch))
    )
    snapshot_root = snapshot_parent / "project"
    snapshot_root.mkdir(mode=0o700)

    try:
        with trusted_root_fd(source_root) as root_fd:
            # Create directories first in depth order.
            directories = [
                entry for entry in source_before.entries if entry.kind == "directory"
            ]
            for entry in sorted(
                directories,
                key=lambda item: (item.path.count("/"), item.path),
            ):
                try:
                    require_before(snapshot_deadline, "workspace snapshot")
                except WorkspaceLimitViolation as exc:
                    raise SnapshotViolation(str(exc)) from exc
                destination = snapshot_root / entry.path
                destination.mkdir(parents=True, exist_ok=False, mode=0o700)

            for entry in source_before.entries:
                if entry.kind != "file":
                    continue
                _copy_file(
                    source_root_fd=root_fd,
                    entry=entry,
                    destination=snapshot_root / entry.path,
                    deadline=snapshot_deadline,
                )

        # Make the snapshot tree non-writable before any scanner or sandbox sees it.
        for entry in sorted(
            directories,
            key=lambda item: (item.path.count("/"), item.path),
            reverse=True,
        ):
            os.chmod(snapshot_root / entry.path, 0o555)
        os.chmod(snapshot_root, 0o555)

        try:
            source_after = build_manifest(
                source_root,
                budget=budget,
                deadline=snapshot_deadline,
            )
        except FilesystemManifestViolation as exc:
            raise SnapshotViolation(str(exc)) from exc

        if _identity_index(source_after) != _identity_index(source_before):
            raise SnapshotViolation(
                "source tree changed while snapshot was created"
            )

        try:
            snapshot_manifest = build_manifest(
                snapshot_root,
                budget=budget,
                deadline=snapshot_deadline,
            )
        except FilesystemManifestViolation as exc:
            raise SnapshotViolation(str(exc)) from exc

        source_hash = _content_hash(source_before)
        snapshot_hash = _content_hash(snapshot_manifest)
        if snapshot_hash != source_hash:
            raise SnapshotViolation(
                "snapshot content does not match admitted source manifest"
            )

        return ProjectSnapshot(
            source_root=source_root,
            snapshot_root=snapshot_root,
            source_hash=source_hash,
            snapshot_hash=snapshot_hash,
        )
    except Exception:
        shutil.rmtree(snapshot_parent, ignore_errors=True)
        raise


def destroy_snapshot(snapshot: ProjectSnapshot) -> None:
    shutil.rmtree(snapshot.snapshot_root.parent, ignore_errors=True)
