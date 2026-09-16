from __future__ import annotations

import ctypes
import errno
import os
import platform
from pathlib import Path
from typing import Iterable


# =============================================================================
# LINUX CONSTANTS
# =============================================================================

# x86_64 syscall numbers.
#
# BULL deliberately refuses to guess syscall numbers on other architectures.
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

PR_SET_NO_NEW_PRIVS = 38


# Landlock filesystem access rights.
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12

# ABI >= 2
LANDLOCK_ACCESS_FS_REFER = 1 << 13

# ABI >= 3
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

# ABI >= 5
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15


READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
)


class LandlockUnavailable(RuntimeError):
    pass


class LandlockError(RuntimeError):
    pass


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


_libc = ctypes.CDLL(
    None,
    use_errno=True,
)

_libc.syscall.restype = ctypes.c_long

_libc.prctl.restype = ctypes.c_int


def _require_supported_architecture() -> None:
    machine = platform.machine().lower()

    if machine not in {
        "x86_64",
        "amd64",
    }:
        raise LandlockUnavailable(
            "BULL Landlock backend v1 currently certifies "
            f"x86_64 only; detected {machine!r}"
        )


def _raise_errno(operation: str) -> None:
    value = ctypes.get_errno()

    raise LandlockError(
        f"{operation} failed: "
        f"[errno {value}] {os.strerror(value)}"
    )


def landlock_abi() -> int:
    """
    Return the kernel's supported Landlock ABI.
    """

    _require_supported_architecture()

    ctypes.set_errno(0)

    result = _libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(0),
        ctypes.c_size_t(0),
        ctypes.c_uint32(
            LANDLOCK_CREATE_RULESET_VERSION
        ),
    )

    if result < 0:
        value = ctypes.get_errno()

        if value in {
            errno.ENOSYS,
            errno.EOPNOTSUPP,
        }:
            raise LandlockUnavailable(
                "Landlock is unavailable or disabled"
            )

        _raise_errno(
            "landlock ABI query"
        )

    return int(result)


def supported_fs_rights(
    abi: int,
) -> int:
    """
    Return only rights defined for this ABI.
    """

    if abi < 1:
        raise LandlockUnavailable(
            f"invalid Landlock ABI {abi}"
        )

    # ABI 1 rights: bits 0 through 12.
    rights = (
        (LANDLOCK_ACCESS_FS_MAKE_SYM << 1)
        - 1
    )

    if abi >= 2:
        rights |= LANDLOCK_ACCESS_FS_REFER

    if abi >= 3:
        rights |= LANDLOCK_ACCESS_FS_TRUNCATE

    if abi >= 5:
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV

    return rights


def writable_access(
    abi: int,
) -> int:
    """
    Project-directory rights.

    Note:
      Device-node creation is intentionally NOT granted.
    """

    access = (
        READ_ACCESS
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    )

    if abi >= 2:
        access |= LANDLOCK_ACCESS_FS_REFER

    if abi >= 3:
        access |= LANDLOCK_ACCESS_FS_TRUNCATE

    return access


def _set_no_new_privs() -> None:
    ctypes.set_errno(0)

    result = _libc.prctl(
        PR_SET_NO_NEW_PRIVS,
        1,
        0,
        0,
        0,
    )

    if result != 0:
        _raise_errno(
            "PR_SET_NO_NEW_PRIVS"
        )


def _create_ruleset(
    handled_access_fs: int,
) -> int:

    attr = _RulesetAttr(
        handled_access_fs=handled_access_fs,
    )

    ctypes.set_errno(0)

    fd = _libc.syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        ctypes.c_uint32(0),
    )

    if fd < 0:
        _raise_errno(
            "landlock_create_ruleset"
        )

    return int(fd)


def _add_path_rule(
    ruleset_fd: int,
    path: Path,
    allowed_access: int,
) -> None:

    path = path.resolve(strict=True)

    parent_fd = os.open(
        str(path),
        os.O_PATH | os.O_CLOEXEC,
    )

    try:
        attr = _PathBeneathAttr(
            allowed_access=allowed_access,
            parent_fd=parent_fd,
        )

        ctypes.set_errno(0)

        result = _libc.syscall(
            _SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(
                LANDLOCK_RULE_PATH_BENEATH
            ),
            ctypes.byref(attr),
            ctypes.c_uint32(0),
        )

        if result < 0:
            _raise_errno(
                f"landlock_add_rule({path})"
            )

    finally:
        os.close(parent_fd)


def _restrict_self(
    ruleset_fd: int,
) -> None:

    ctypes.set_errno(0)

    result = _libc.syscall(
        _SYS_LANDLOCK_RESTRICT_SELF,
        ctypes.c_int(ruleset_fd),
        ctypes.c_uint32(0),
    )

    if result < 0:
        _raise_errno(
            "landlock_restrict_self"
        )


def apply_landlock(
    *,
    read_only: Iterable[
        str | Path
    ] = (),
    read_write: Iterable[
        str | Path
    ] = (),
) -> int:
    """
    Apply an irreversible Landlock filesystem domain
    to the CURRENT PROCESS.

    Returns:
        detected Landlock ABI

    BULL fails closed if Landlock cannot be activated.
    """

    abi = landlock_abi()

    handled = supported_fs_rights(
        abi
    )

    ruleset_fd = _create_ruleset(
        handled
    )

    try:
        for raw_path in read_only:
            _add_path_rule(
                ruleset_fd,
                Path(raw_path),
                READ_ACCESS,
            )

        rw_access = writable_access(
            abi
        )

        for raw_path in read_write:
            _add_path_rule(
                ruleset_fd,
                Path(raw_path),
                rw_access,
            )

        # Required before an unprivileged
        # process may restrict itself.
        _set_no_new_privs()

        _restrict_self(
            ruleset_fd
        )

    finally:
        os.close(ruleset_fd)

    return abi
