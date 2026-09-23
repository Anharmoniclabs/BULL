from __future__ import annotations

from dataclasses import dataclass
import os
import resource


@dataclass(frozen=True)
class ResourceBudget:

    # Address-space ceiling.
    memory_bytes: int = 512 * 1024 * 1024

    # CPU seconds.
    cpu_seconds: int = 30

    # Maximum child processes.
    processes: int = 64

    # Open descriptors.
    open_files: int = 256

    # Maximum single output/file size.
    file_bytes: int = 64 * 1024 * 1024

    # Core files are never useful inside BULL sandbox.
    core_bytes: int = 0


def _safe_limit(
    which: int,
    value: int,
) -> None:

    current_soft, current_hard = (
        resource.getrlimit(which)
    )

    # Do not attempt to raise an outer host/container limit.
    if current_hard == resource.RLIM_INFINITY:
        hard = value
    else:
        hard = min(
            current_hard,
            value,
        )

    soft = min(
        value,
        hard,
    )

    resource.setrlimit(
        which,
        (
            soft,
            hard,
        ),
    )


def apply_resource_budget(
    budget: ResourceBudget,
    *,
    enforce_uid_process_limit: bool = True,
) -> None:

    _safe_limit(
        resource.RLIMIT_AS,
        int(budget.memory_bytes),
    )

    _safe_limit(
        resource.RLIMIT_CPU,
        int(budget.cpu_seconds),
    )

    if enforce_uid_process_limit:
        _safe_limit(
            resource.RLIMIT_NPROC,
            int(budget.processes),
        )

    _safe_limit(
        resource.RLIMIT_NOFILE,
        int(budget.open_files),
    )

    _safe_limit(
        resource.RLIMIT_FSIZE,
        int(budget.file_bytes),
    )

    _safe_limit(
        resource.RLIMIT_CORE,
        int(budget.core_bytes),
    )


def current_budget() -> dict:

    result = {}

    mapping = {
        "address_space":
            resource.RLIMIT_AS,

        "cpu":
            resource.RLIMIT_CPU,

        "processes":
            resource.RLIMIT_NPROC,

        "open_files":
            resource.RLIMIT_NOFILE,

        "file_size":
            resource.RLIMIT_FSIZE,

        "core":
            resource.RLIMIT_CORE,
    }

    for name, which in mapping.items():

        result[name] = (
            resource.getrlimit(
                which
            )
        )

    return result
