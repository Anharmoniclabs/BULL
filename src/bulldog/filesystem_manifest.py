from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import stat

from .workspace_limits import (
    WorkspaceBudget,
    WorkspaceLimitViolation,
    deadline_after,
    require_before,
)


class FilesystemManifestViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: str
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str | None


@dataclass(frozen=True)
class FilesystemManifest:
    root: str
    device: int
    entries: tuple[ManifestEntry, ...]
    total_bytes: int = 0
    file_count: int = 0


def _limit_error(exc: WorkspaceLimitViolation) -> FilesystemManifestViolation:
    return FilesystemManifestViolation(str(exc))


def _check_path_budget(relative: str, *, depth: int, budget: WorkspaceBudget) -> None:
    if depth > budget.max_depth:
        raise FilesystemManifestViolation(
            f"directory depth exceeds limit ({budget.max_depth}): {relative}"
        )
    if len(relative.encode("utf-8")) > budget.max_path_bytes:
        raise FilesystemManifestViolation(
            f"path length exceeds limit ({budget.max_path_bytes} bytes): {relative}"
        )


def _hash_fd(fd: int, *, deadline: float) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        try:
            require_before(deadline, "filesystem manifest")
        except WorkspaceLimitViolation as exc:
            raise _limit_error(exc) from exc
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def build_manifest(
    root: str | Path,
    *,
    require_same_device: bool = True,
    reject_setid: bool = True,
    budget: WorkspaceBudget | None = None,
    deadline: float | None = None,
) -> FilesystemManifest:
    """Build a bounded manifest using directory-FD relative opens.

    The walk never follows symlinks, detects replacement between metadata
    inspection and file open, rejects mount/device changes and hardlinks, and
    enforces hard limits before snapshotting or malware scanning can consume
    unbounded host resources.
    """

    budget = budget or WorkspaceBudget()
    try:
        budget.validate()
    except WorkspaceLimitViolation as exc:
        raise _limit_error(exc) from exc

    if deadline is None:
        deadline = deadline_after(budget.manifest_timeout_seconds)

    root_path = Path(root).resolve(strict=True)
    root_fd = os.open(
        root_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        root_stat = os.fstat(root_fd)
        root_device = int(root_stat.st_dev)
        entries: list[ManifestEntry] = []
        counters = {"files": 0, "bytes": 0, "entries": 0}

        def walk(dir_fd: int, prefix: tuple[str, ...], depth: int) -> None:
            try:
                require_before(deadline, "filesystem manifest")
            except WorkspaceLimitViolation as exc:
                raise _limit_error(exc) from exc

            try:
                names = sorted(os.listdir(dir_fd))
            except OSError as exc:
                raise FilesystemManifestViolation(
                    f"unable to enumerate workspace directory: {exc}"
                ) from exc

            for name in names:
                if name == ".git":
                    continue

                relative_parts = prefix + (name,)
                relative = "/".join(relative_parts)
                _check_path_budget(relative, depth=depth, budget=budget)

                counters["entries"] += 1
                if counters["entries"] > budget.max_files + budget.max_files:
                    raise FilesystemManifestViolation(
                        "workspace entry count exceeds bounded admission limit"
                    )

                try:
                    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise FilesystemManifestViolation(
                        f"tree changed during manifest construction: {relative}"
                    ) from exc

                if stat.S_ISLNK(st.st_mode):
                    raise FilesystemManifestViolation(
                        f"symlink rejected: {relative}"
                    )

                if require_same_device and st.st_dev != root_device:
                    raise FilesystemManifestViolation(
                        "filesystem boundary/mount point rejected: " + relative
                    )

                if reject_setid and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise FilesystemManifestViolation(
                        "setuid/setgid entry rejected: " + relative
                    )

                if stat.S_ISDIR(st.st_mode):
                    flags = (
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_NOFOLLOW
                        | os.O_CLOEXEC
                    )
                    try:
                        child_fd = os.open(name, flags, dir_fd=dir_fd)
                    except OSError as exc:
                        raise FilesystemManifestViolation(
                            f"directory open rejected: {relative}: {exc}"
                        ) from exc
                    try:
                        opened = os.fstat(child_fd)
                        if (
                            opened.st_dev != st.st_dev
                            or opened.st_ino != st.st_ino
                            or not stat.S_ISDIR(opened.st_mode)
                        ):
                            raise FilesystemManifestViolation(
                                f"directory changed during admission: {relative}"
                            )
                        entries.append(
                            ManifestEntry(
                                path=relative,
                                kind="directory",
                                device=int(opened.st_dev),
                                inode=int(opened.st_ino),
                                mode=int(opened.st_mode),
                                uid=int(opened.st_uid),
                                gid=int(opened.st_gid),
                                size=int(opened.st_size),
                                sha256=None,
                            )
                        )
                        walk(child_fd, relative_parts, depth + 1)
                    finally:
                        os.close(child_fd)
                    continue

                if not stat.S_ISREG(st.st_mode):
                    raise FilesystemManifestViolation(
                        "special filesystem object rejected: " + relative
                    )

                if st.st_nlink > 1:
                    raise FilesystemManifestViolation(
                        "hardlink rejected: " + relative
                    )
                if st.st_size > budget.max_file_bytes:
                    raise FilesystemManifestViolation(
                        f"file exceeds size limit ({budget.max_file_bytes}): {relative}"
                    )

                counters["files"] += 1
                counters["bytes"] += int(st.st_size)
                if counters["files"] > budget.max_files:
                    raise FilesystemManifestViolation(
                        f"file count exceeds limit ({budget.max_files})"
                    )
                if counters["bytes"] > budget.max_total_bytes:
                    raise FilesystemManifestViolation(
                        f"workspace bytes exceed limit ({budget.max_total_bytes})"
                    )

                try:
                    fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=dir_fd,
                    )
                except OSError as exc:
                    raise FilesystemManifestViolation(
                        f"file open rejected: {relative}: {exc}"
                    ) from exc
                try:
                    opened = os.fstat(fd)
                    if (
                        opened.st_dev != st.st_dev
                        or opened.st_ino != st.st_ino
                        or opened.st_size != st.st_size
                        or opened.st_nlink != 1
                        or not stat.S_ISREG(opened.st_mode)
                    ):
                        raise FilesystemManifestViolation(
                            f"file changed during admission: {relative}"
                        )
                    digest = _hash_fd(fd, deadline=deadline)
                    after = os.fstat(fd)
                    if (
                        after.st_size != opened.st_size
                        or after.st_mtime_ns != opened.st_mtime_ns
                        or after.st_ctime_ns != opened.st_ctime_ns
                    ):
                        raise FilesystemManifestViolation(
                            f"file changed while hashing: {relative}"
                        )
                finally:
                    os.close(fd)

                entries.append(
                    ManifestEntry(
                        path=relative,
                        kind="file",
                        device=int(opened.st_dev),
                        inode=int(opened.st_ino),
                        mode=int(opened.st_mode),
                        uid=int(opened.st_uid),
                        gid=int(opened.st_gid),
                        size=int(opened.st_size),
                        sha256=digest,
                    )
                )

        walk(root_fd, (), 1)
        return FilesystemManifest(
            root=str(root_path),
            device=root_device,
            entries=tuple(entries),
            total_bytes=int(counters["bytes"]),
            file_count=int(counters["files"]),
        )
    finally:
        os.close(root_fd)
