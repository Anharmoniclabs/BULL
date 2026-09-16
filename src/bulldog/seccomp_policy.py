from __future__ import annotations

import ctypes
import ctypes.util
import errno


class SeccompUnavailable(RuntimeError):
    pass


class SeccompError(RuntimeError):
    pass


# libseccomp action constants.
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_BASE = 0x00050000


def SCMP_ACT_ERRNO(value: int) -> int:
    return (
        SCMP_ACT_ERRNO_BASE
        | (value & 0xFFFF)
    )


# Initial BULL kernel-control deny set.
DENIED_SYSCALLS = (
    "mount",
    "umount2",
    "pivot_root",
    "ptrace",
    "fspick",
    "fsmount",
    "fsconfig",
    "fsopen",
    "open_tree",
    "move_mount",
    "pidfd_getfd",
    "clone3",
    "name_to_handle_at",
    "open_by_handle_at",
    "io_uring_register",
    "io_uring_enter",
    "io_uring_setup",
    "userfaultfd",
    "process_vm_writev",
    "process_vm_readv",
    "bpf",
    "perf_event_open",
    "keyctl",
    "add_key",
    "request_key",
    "setns",
    "unshare",
    "kexec_load",
    "finit_module",
    "init_module",
    "delete_module",
    "reboot",
)


def _load_libseccomp():
    """
    Load libseccomp without depending on ldconfig/find_library.

    BULL's sandbox intentionally exposes only a minimal runtime,
    so ctypes.util.find_library() may fail even though the shared
    object is present and resolvable by the ELF dynamic loader.
    """

    candidates = [
        "libseccomp.so.2",
        "libseccomp.so",
    ]

    discovered = ctypes.util.find_library(
        "seccomp"
    )

    if discovered:
        candidates.append(
            discovered
        )

    errors = []

    for candidate in candidates:

        try:

            return ctypes.CDLL(
                candidate,
                use_errno=True,
            )

        except OSError as exc:

            errors.append(
                f"{candidate}: {exc}"
            )

    raise SeccompUnavailable(
        "unable to load libseccomp; "
        + " | ".join(errors)
    )


_lib = _load_libseccomp()


# scmp_filter_ctx seccomp_init(uint32_t def_action)
_lib.seccomp_init.argtypes = [
    ctypes.c_uint32,
]

_lib.seccomp_init.restype = (
    ctypes.c_void_p
)


# void seccomp_release(scmp_filter_ctx ctx)
_lib.seccomp_release.argtypes = [
    ctypes.c_void_p,
]

_lib.seccomp_release.restype = None


# int seccomp_syscall_resolve_name(const char *name)
_lib.seccomp_syscall_resolve_name.argtypes = [
    ctypes.c_char_p,
]

_lib.seccomp_syscall_resolve_name.restype = (
    ctypes.c_int
)


# int seccomp_rule_add(
#     scmp_filter_ctx ctx,
#     uint32_t action,
#     int syscall,
#     unsigned int arg_cnt,
#     ...
# )
_lib.seccomp_rule_add.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
]

_lib.seccomp_rule_add.restype = (
    ctypes.c_int
)


# int seccomp_load(scmp_filter_ctx ctx)
_lib.seccomp_load.argtypes = [
    ctypes.c_void_p,
]

_lib.seccomp_load.restype = (
    ctypes.c_int
)


def _check(
    rc: int,
    operation: str,
) -> None:

    # libseccomp returns negative errno values.
    if rc < 0:
        value = -rc

        raise SeccompError(
            f"{operation} failed: "
            f"[errno {value}] "
            f"{errno.errorcode.get(value, 'UNKNOWN')}"
        )


def install_bull_seccomp(
    *,
    denied_syscalls=DENIED_SYSCALLS,
    errno_value: int = errno.EPERM,
) -> tuple[str, ...]:
    """
    Install the BULL v1 syscall policy on the CURRENT PROCESS.

    Default behavior:
        ALLOW

    Explicit high-risk syscalls:
        return EPERM without executing.

    Filters are inherited by children and across exec.
    """

    ctx = _lib.seccomp_init(
        SCMP_ACT_ALLOW
    )

    if not ctx:
        raise SeccompError(
            "seccomp_init returned NULL"
        )

    installed: list[str] = []

    try:
        action = SCMP_ACT_ERRNO(
            errno_value
        )

        for name in denied_syscalls:

            number = (
                _lib
                .seccomp_syscall_resolve_name(
                    name.encode("ascii")
                )
            )

            # Unknown syscall on this architecture.
            # Skip instead of guessing syscall numbers.
            if number < 0:
                continue

            rc = _lib.seccomp_rule_add(
                ctx,
                action,
                number,
                0,
            )

            _check(
                rc,
                f"seccomp_rule_add({name})",
            )

            installed.append(name)

        rc = _lib.seccomp_load(
            ctx
        )

        _check(
            rc,
            "seccomp_load",
        )

    finally:
        _lib.seccomp_release(
            ctx
        )

    return tuple(
        installed
    )
