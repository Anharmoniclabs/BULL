from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import os
from pathlib import Path, PurePosixPath
from typing import Iterator


class SecurePathViolation(RuntimeError):
    pass


# Linux openat2 UAPI. Syscall number 437 is shared by modern x86_64/aarch64.
_SYS_OPENAT2 = 437
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


_libc = ctypes.CDLL(None, use_errno=True)


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


def _openat2(
    root_fd: int,
    relative_path: str,
    *,
    flags: int,
    mode: int,
) -> int | None:
    how = _OpenHow(
        flags=int(flags),
        mode=int(mode if flags & os.O_CREAT else 0),
        resolve=(
            _RESOLVE_BENEATH
            | _RESOLVE_NO_SYMLINKS
            | _RESOLVE_NO_MAGICLINKS
        ),
    )
    encoded = os.fsencode(relative_path)
    result = int(
        _libc.syscall(
            _SYS_OPENAT2,
            int(root_fd),
            ctypes.c_char_p(encoded),
            ctypes.byref(how),
            ctypes.sizeof(how),
        )
    )
    if result >= 0:
        return result

    err = ctypes.get_errno()
    if err in {errno.ENOSYS, errno.EINVAL, errno.E2BIG}:
        # Older kernels fall back to the component-by-component dirfd walk.
        return None
    raise SecurePathViolation(
        f"openat2 rejected {relative_path!r}: [errno {err}] {os.strerror(err)}"
    )


def open_beneath(
    root_fd: int,
    relative_path: str,
    *,
    flags: int = os.O_RDONLY,
    mode: int = 0o600,
    directory: bool = False,
) -> int:
    """Atomically open beneath a trusted root without symlinks or magic links.

    On modern Linux this uses openat2(RESOLVE_BENEATH | NO_SYMLINKS |
    NO_MAGICLINKS). Older kernels use a secure directory-FD component walk
    with O_NOFOLLOW on every reopen.
    """

    parts = _components(relative_path)
    normalized = "/".join(parts)
    final_flags = int(flags) | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        final_flags |= os.O_DIRECTORY

    opened = _openat2(
        root_fd,
        normalized,
        flags=final_flags,
        mode=mode,
    )
    if opened is not None:
        return opened

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
