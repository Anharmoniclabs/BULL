from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path


class LandlockUnavailable(RuntimeError):
    pass


class LandlockError(RuntimeError):
    pass


# Linux UAPI constants.
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13
ACCESS_TRUNCATE = 1 << 14

_BASE_ACCESS = (
    ACCESS_EXECUTE
    | ACCESS_WRITE_FILE
    | ACCESS_READ_FILE
    | ACCESS_READ_DIR
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
)


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


libc = ctypes.CDLL(None, use_errno=True)

# landlock syscall numbers are defined in asm-generic and match x86_64/aarch64.
_SYS_CREATE_RULESET = 444
_SYS_ADD_RULE = 445
_SYS_RESTRICT_SELF = 446


def _syscall(number: int, *args) -> int:
    result = int(libc.syscall(number, *args))
    if result < 0:
        err = ctypes.get_errno()
        if err in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            raise LandlockUnavailable(os.strerror(err))
        raise LandlockError(f"landlock syscall failed: [errno {err}] {os.strerror(err)}")
    return result


def _handled_access(abi: int) -> int:
    handled = _BASE_ACCESS
    if abi >= 2:
        handled |= ACCESS_REFER
    if abi >= 3:
        handled |= ACCESS_TRUNCATE
    return handled


def _add_path_rule(ruleset_fd: int, path: str, allowed: int) -> None:
    target = Path(path)
    if not target.exists():
        return
    path_fd = os.open(
        target,
        getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        attr = _PathBeneathAttr(
            allowed_access=allowed,
            parent_fd=path_fd,
        )
        _syscall(
            _SYS_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(attr),
            0,
        )
    finally:
        os.close(path_fd)


def install_bull_landlock(*, workspace_writable: bool = False) -> int:
    """Restrict filesystem access to the sandbox root's explicit mounts.

    Landlock is layered after chroot/mount isolation and before seccomp. Strict
    production treats absence of Landlock as a backend-certification failure.
    """

    abi = _syscall(
        _SYS_CREATE_RULESET,
        0,
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    handled = _handled_access(abi)
    attr = _RulesetAttr(handled_access_fs=handled)
    ruleset_fd = _syscall(
        _SYS_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        0,
    )
    try:
        read_only = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
        read_write = handled
        device_access = ACCESS_READ_FILE | ACCESS_WRITE_FILE | ACCESS_READ_DIR

        for path in (
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/etc",
            "/bull_runtime",
        ):
            _add_path_rule(ruleset_fd, path, read_only & handled)

        _add_path_rule(
            ruleset_fd,
            "/workspace",
            (read_write if workspace_writable else read_only) & handled,
        )
        _add_path_rule(ruleset_fd, "/tmp", read_write & handled)
        _add_path_rule(ruleset_fd, "/dev", device_access & handled)

        _syscall(_SYS_RESTRICT_SELF, ruleset_fd, 0)
    finally:
        os.close(ruleset_fd)

    return abi
