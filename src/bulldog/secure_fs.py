from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
from typing import Iterator


class SecurePathViolation(RuntimeError):
    pass


def _components(relative_path: str) -> tuple[str, ...]:
    raw = str(relative_path).replace("\\", "/")
    path = PurePosixPath(raw)
    if path.is_absolute():
        raise SecurePathViolation("secure path must be relative to trusted root")
    parts = tuple(path.parts)
    if not parts:
        raise SecurePathViolation("secure path cannot be empty")
    for part in parts:
        if part in {"", ".", ".."}:
            raise SecurePathViolation("unsafe path component")
        if "\x00" in part:
            raise SecurePathViolation("NUL byte in path component")
    return parts


@contextmanager
def trusted_root_fd(root: str | Path) -> Iterator[int]:
    root_path = Path(root).resolve(strict=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    fd = os.open(root_path, flags)
    try:
        yield fd
    finally:
        os.close(fd)


def open_beneath(
    root_fd: int,
    relative_path: str,
    *,
    flags: int = os.O_RDONLY,
    mode: int = 0o600,
    directory: bool = False,
) -> int:
    """Open beneath a trusted directory FD without following symlinks.

    This is the portable dirfd/O_NOFOLLOW equivalent of an openat2
    RESOLVE_BENEATH + RESOLVE_NO_SYMLINKS walk. Every intermediate path
    component is opened as a directory with O_NOFOLLOW, so a concurrent
    symlink swap cannot redirect the final open outside the trusted root.
    """

    parts = _components(relative_path)
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd

        final_flags = flags | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory:
            final_flags |= os.O_DIRECTORY
        return os.open(parts[-1], final_flags, mode, dir_fd=current)
    except OSError as exc:
        raise SecurePathViolation(
            f"kernel-constrained open rejected {relative_path!r}: {exc}"
        ) from exc
    finally:
        os.close(current)


def stat_beneath(root_fd: int, relative_path: str) -> os.stat_result:
    fd = open_beneath(root_fd, relative_path)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)
