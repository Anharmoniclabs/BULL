from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import math
import os
import resource
import shutil
import subprocess
import sys
import tempfile

from .cgroup_scope import CgroupV2Scope
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
    cleanup_root: Path | None = None


def _force_remove_tree(path: Path) -> None:
    if not path.exists():
        return
    for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
        root_path = Path(root)
        try:
            os.chmod(root_path, 0o700)
        except OSError:
            pass
        for name in files:
            target = root_path / name
            try:
                os.chmod(target, 0o600, follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
        for name in dirs:
            target = root_path / name
            try:
                os.chmod(target, 0o700, follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    shutil.rmtree(path, ignore_errors=False)


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

    snapshot_parent = Path(tempfile.mkdtemp(prefix="bull_snapshot_", dir=str(scratch)))
    snapshot_root = snapshot_parent / "project"
    snapshot_root.mkdir(mode=0o700)

    try:
        with trusted_root_fd(source_root) as root_fd:
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
            raise SnapshotViolation("source tree changed while snapshot was created")

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
            cleanup_root=snapshot_parent,
        )
    except Exception:
        try:
            _force_remove_tree(snapshot_parent)
        except OSError:
            pass
        raise


def _worker_environment(budget: WorkspaceBudget) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "HOME": "/nonexistent",
        "TMPDIR": "/tmp",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "BULL_MAX_WORKSPACE_FILES": str(budget.max_files),
        "BULL_MAX_WORKSPACE_BYTES": str(budget.max_total_bytes),
        "BULL_MAX_WORKSPACE_FILE_BYTES": str(budget.max_file_bytes),
        "BULL_MAX_WORKSPACE_DEPTH": str(budget.max_depth),
        "BULL_MAX_WORKSPACE_PATH_BYTES": str(budget.max_path_bytes),
        "BULL_MANIFEST_TIMEOUT_SECONDS": str(budget.manifest_timeout_seconds),
        "BULL_SNAPSHOT_TIMEOUT_SECONDS": str(budget.snapshot_timeout_seconds),
        "BULL_MALWARE_SCAN_TIMEOUT_SECONDS": str(budget.malware_scan_timeout_seconds),
        "BULL_SNAPSHOT_MIN_FREE_BYTES": str(budget.snapshot_min_free_bytes),
    }


def create_snapshot_isolated(
    source_root: str | Path,
    *,
    budget: WorkspaceBudget,
    scratch_root: str | Path,
) -> ProjectSnapshot:
    """Run hostile tree admission/copying in a killable cgroup/rlimit worker."""

    source = Path(source_root).resolve(strict=True)
    scratch = Path(scratch_root).resolve(strict=True)
    worker_root = Path(tempfile.mkdtemp(prefix="bull_admission_", dir=str(scratch)))

    scope = CgroupV2Scope.from_environment(
        memory_bytes=768 * 1024 * 1024,
        processes=8,
        cpu_quota_us=100_000,
        name_prefix="bull-admission",
    )
    context = scope if scope is not None else nullcontext(None)

    def _limits(active_scope: CgroupV2Scope | None) -> None:
        memory = 768 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        cpu = max(1, int(math.ceil(budget.snapshot_timeout_seconds)) + 2)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if active_scope is not None:
            active_scope.attach_current()

    try:
        with context as active_scope:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "bulldog.snapshot_worker",
                    str(source),
                    str(worker_root),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=budget.snapshot_timeout_seconds + 5.0,
                env=_worker_environment(budget),
                cwd="/",
                preexec_fn=(lambda: _limits(active_scope)) if os.name == "posix" else None,
            )
        if proc.returncode != 0:
            raise SnapshotViolation(
                "isolated snapshot worker failed: " + (proc.stderr.strip()[-2000:] or "unknown error")
            )

        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise SnapshotViolation("isolated snapshot worker returned invalid output")
        data = json.loads(lines[0])
        snapshot_path = Path(str(data["snapshot_root"])).resolve(strict=True)
        try:
            snapshot_path.relative_to(worker_root)
        except ValueError as exc:
            raise SnapshotViolation("snapshot worker returned path outside scratch scope") from exc
        if Path(str(data["source_root"])).resolve(strict=True) != source:
            raise SnapshotViolation("snapshot worker source identity mismatch")

        return ProjectSnapshot(
            source_root=source,
            snapshot_root=snapshot_path,
            source_hash=str(data["source_hash"]),
            snapshot_hash=str(data["snapshot_hash"]),
            cleanup_root=worker_root,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        try:
            _force_remove_tree(worker_root)
        except OSError:
            pass
        if isinstance(exc, SnapshotViolation):
            raise
        raise SnapshotViolation(f"isolated snapshot worker failed: {exc}") from exc
    except Exception:
        try:
            _force_remove_tree(worker_root)
        except OSError:
            pass
        raise


def destroy_snapshot(snapshot: ProjectSnapshot) -> None:
    root = snapshot.cleanup_root or snapshot.snapshot_root.parent
    _force_remove_tree(root)
