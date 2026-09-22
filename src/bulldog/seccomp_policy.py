from __future__ import annotations

import ctypes
import ctypes.util
import errno


class SeccompUnavailable(RuntimeError):
    pass


class SeccompError(RuntimeError):
    pass


SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_BASE = 0x00050000

# BULL-PENTEST-HARDENING: argument-filtered socket policy
# libseccomp comparison operators from enum scmp_compare.
SCMP_CMP_EQ = 4
SCMP_CMP_MASKED_EQ = 7

# Linux UAPI values are stable across supported architectures.
_AF_UNIX = 1
_AF_INET = 2
_AF_INET6 = 10
_SOCK_STREAM = 1
_SOCK_DGRAM = 2
_SOCK_SEQPACKET = 5
_SOCK_TYPE_MASK = 0xF


class _ScmpArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def SCMP_ACT_ERRNO(value: int) -> int:
    return SCMP_ACT_ERRNO_BASE | (value & 0xFFFF)


# Compatibility profile: default allow with an explicit kernel-control deny set.
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


# Production profile: default deny, then permit a deliberately broad userland
# baseline sufficient for normal dynamically-linked CLI/Python workloads inside
# BULL's already-isolated mount/PID/network namespaces. Dangerous kernel-control
# surfaces are absent because anything not listed returns EPERM.
STRICT_ALLOWED_SYSCALLS = (
    # process / execution
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "clone",
    "fork",
    "vfork",
    "wait4",
    "waitid",
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getgroups",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "setgroups",
    "setsid",
    "getpgid",
    "setpgid",
    "getpgrp",
    # memory / runtime
    "brk",
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "madvise",
    "mlock",
    "munlock",
    "futex",
    "rseq",
    "set_tid_address",
    "set_robust_list",
    "arch_prctl",
    "prctl",
    "membarrier",
    # signals / scheduling / time
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "rt_sigsuspend",
    "rt_sigpending",
    "rt_sigtimedwait",
    "sigaltstack",
    "kill",
    "tgkill",
    "sched_yield",
    "sched_getaffinity",
    "sched_setaffinity",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    "time",
    "times",
    # file descriptors / filesystem inside the isolated root
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "preadv",
    "pwritev",
    "close",
    "close_range",
    "lseek",
    "open",
    "openat",
    "creat",
    "newfstatat",
    "stat",
    "lstat",
    "fstat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getdents",
    "getdents64",
    "getcwd",
    "chdir",
    "fchdir",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
    "lchown",
    "truncate",
    "ftruncate",
    "fsync",
    "fdatasync",
    "sync_file_range",
    "umask",
    "fcntl",
    "ioctl",
    "dup",
    "dup2",
    "dup3",
    "flock",
    "pipe",
    "pipe2",
    "sendfile",
    "copy_file_range",
    "splice",
    "tee",
    # event / multiplexing
    "select",
    "pselect6",
    "poll",
    "ppoll",
    "epoll_create",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd",
    "eventfd2",
    "signalfd",
    "signalfd4",
    "timerfd_create",
    "timerfd_settime",
    "timerfd_gettime",
    # local IPC and sockets. The network namespace supplies the network boundary;
    # allowing socket syscalls is required for AF_UNIX brokers and normal runtimes.
    "socket",
    "socketpair",
    "bind",
    "listen",
    "accept",
    "accept4",
    "connect",
    "getsockname",
    "getpeername",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
    # identity / environment / misc runtime discovery
    "uname",
    "sysinfo",
    "getrandom",
    "getrlimit",
    "setrlimit",
    "prlimit64",
    "getrusage",
    "getcpu",
    "personality",
)


def _load_libseccomp():
    candidates = ["libseccomp.so.2", "libseccomp.so"]
    discovered = ctypes.util.find_library("seccomp")
    if discovered:
        candidates.append(discovered)

    errors = []
    for candidate in candidates:
        try:
            return ctypes.CDLL(candidate, use_errno=True)
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")

    raise SeccompUnavailable(
        "unable to load libseccomp; " + " | ".join(errors)
    )


_lib = _load_libseccomp()

_lib.seccomp_init.argtypes = [ctypes.c_uint32]
_lib.seccomp_init.restype = ctypes.c_void_p
_lib.seccomp_release.argtypes = [ctypes.c_void_p]
_lib.seccomp_release.restype = None
_lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
_lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
_lib.seccomp_rule_add.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
]
_lib.seccomp_rule_add.restype = ctypes.c_int
_lib.seccomp_rule_add_array.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.POINTER(_ScmpArgCmp),
]
_lib.seccomp_rule_add_array.restype = ctypes.c_int
_lib.seccomp_load.argtypes = [ctypes.c_void_p]
_lib.seccomp_load.restype = ctypes.c_int


def _check(rc: int, operation: str) -> None:
    if rc < 0:
        value = -rc
        raise SeccompError(
            f"{operation} failed: [errno {value}] "
            f"{errno.errorcode.get(value, 'UNKNOWN')}"
        )


def _resolve(name: str) -> int | None:
    number = _lib.seccomp_syscall_resolve_name(name.encode("ascii"))
    if number < 0:
        return None
    return number


def _add_cmp_rule(
    ctx,
    *,
    action: int,
    syscall_number: int,
    comparisons: tuple[_ScmpArgCmp, ...],
    label: str,
) -> None:
    if not comparisons:
        raise SeccompError("comparison rule must contain at least one argument constraint")
    array_type = _ScmpArgCmp * len(comparisons)
    array = array_type(*comparisons)
    _check(
        _lib.seccomp_rule_add_array(
            ctx,
            action,
            syscall_number,
            len(comparisons),
            array,
        ),
        f"seccomp_rule_add_array({label})",
    )


def install_bull_seccomp(
    *,
    profile: str = "compat",
    denied_syscalls=DENIED_SYSCALLS,
    allowed_syscalls=STRICT_ALLOWED_SYSCALLS,
    errno_value: int = errno.EPERM,
) -> tuple[str, ...]:
    """Install BULL's seccomp policy on the current process.

    ``compat`` keeps the historical default-ALLOW blacklist for development.
    ``strict`` is the production profile: default EPERM with an explicit
    userland allowlist. Both policies are inherited across exec and children.
    """

    profile = str(profile).strip().lower()
    if profile not in {"compat", "strict"}:
        raise SeccompError(f"unknown seccomp profile: {profile}")

    default_action = (
        SCMP_ACT_ALLOW
        if profile == "compat"
        else SCMP_ACT_ERRNO(errno_value)
    )
    ctx = _lib.seccomp_init(default_action)
    if not ctx:
        raise SeccompError("seccomp_init returned NULL")

    installed: list[str] = []
    try:
        if profile == "compat":
            action = SCMP_ACT_ERRNO(errno_value)
            names = denied_syscalls
        else:
            action = SCMP_ACT_ALLOW
            # socket() is installed below with argument constraints. A generic
            # socket allow rule would make SOCK_RAW reachable again.
            names = tuple(name for name in allowed_syscalls if name != "socket")

        for name in names:
            number = _resolve(name)
            if number is None:
                continue
            _check(
                _lib.seccomp_rule_add(ctx, action, number, 0),
                f"seccomp_rule_add({name})",
            )
            installed.append(name)

        if profile == "strict" and "socket" in allowed_syscalls:
            socket_nr = _resolve("socket")
            if socket_nr is not None:
                # Local broker/runtime sockets remain available.
                _add_cmp_rule(
                    ctx,
                    action=SCMP_ACT_ALLOW,
                    syscall_number=socket_nr,
                    comparisons=(
                        _ScmpArgCmp(0, SCMP_CMP_EQ, _AF_UNIX, 0),
                    ),
                    label="socket:AF_UNIX",
                )
                installed.append("socket(AF_UNIX)")

                # Internet-family sockets are limited to ordinary non-raw
                # socket types. SOCK_CLOEXEC/SOCK_NONBLOCK flags are ignored
                # by masking against Linux's low-nibble SOCK_TYPE_MASK.
                for domain, domain_name in (
                    (_AF_INET, "AF_INET"),
                    (_AF_INET6, "AF_INET6"),
                ):
                    for sock_type, type_name in (
                        (_SOCK_STREAM, "SOCK_STREAM"),
                        (_SOCK_DGRAM, "SOCK_DGRAM"),
                        (_SOCK_SEQPACKET, "SOCK_SEQPACKET"),
                    ):
                        _add_cmp_rule(
                            ctx,
                            action=SCMP_ACT_ALLOW,
                            syscall_number=socket_nr,
                            comparisons=(
                                _ScmpArgCmp(0, SCMP_CMP_EQ, domain, 0),
                                _ScmpArgCmp(
                                    1,
                                    SCMP_CMP_MASKED_EQ,
                                    _SOCK_TYPE_MASK,
                                    sock_type,
                                ),
                            ),
                            label=f"socket:{domain_name}:{type_name}",
                        )
                        installed.append(
                            f"socket({domain_name},{type_name})"
                        )

        _check(_lib.seccomp_load(ctx), "seccomp_load")
    finally:
        _lib.seccomp_release(ctx)

    return tuple(installed)
