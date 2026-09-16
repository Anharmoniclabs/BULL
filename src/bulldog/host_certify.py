from __future__ import annotations

import ctypes.util
import os
from pathlib import Path
import shutil


def certify_host() -> dict:

    checks = {
        "linux":
            os.name == "posix",

        "unshare":
            shutil.which(
                "unshare"
            ) is not None,

        "mount":
            shutil.which(
                "mount"
            ) is not None,

        "chroot":
            shutil.which(
                "chroot"
            ) is not None,

        "network_namespace":
            Path(
                "/proc/self/ns/net"
            ).exists(),

        "pid_namespace":
            Path(
                "/proc/self/ns/pid"
            ).exists(),

        "mount_namespace":
            Path(
                "/proc/self/ns/mnt"
            ).exists(),

        "user_namespace":
            Path(
                "/proc/self/ns/user"
            ).exists(),

        "cgroup_v2":
            Path(
                "/sys/fs/cgroup/cgroup.controllers"
            ).exists(),

        "libseccomp":
            ctypes.util.find_library(
                "seccomp"
            ) is not None,
    }

    return {
        "checks":
            checks,

        "certified":
            all(
                checks.values()
            ),
    }
