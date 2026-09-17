from __future__ import annotations

import ctypes.util
import os
from pathlib import Path
import shutil
import tempfile


def certify_host(
    *,
    dynamic: bool = False,
    seccomp_profile: str = "strict",
) -> dict:
    """Certify the host capabilities BULL depends on.

    Static checks prove prerequisites are present. ``dynamic=True`` additionally
    launches the real NamespaceSandbox and requires its nonce-bound backend
    attestation, so a host where unshare/mount/seccomp are installed but blocked
    by policy does not receive a production certification.
    """

    checks = {
        "linux": os.name == "posix",
        "unshare": shutil.which("unshare") is not None,
        "mount": shutil.which("mount") is not None,
        "chroot": shutil.which("chroot") is not None,
        "network_namespace": Path("/proc/self/ns/net").exists(),
        "pid_namespace": Path("/proc/self/ns/pid").exists(),
        "mount_namespace": Path("/proc/self/ns/mnt").exists(),
        "user_namespace": Path("/proc/self/ns/user").exists(),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
        "libseccomp": ctypes.util.find_library("seccomp") is not None,
    }

    result = {
        "checks": checks,
        "static_certified": all(checks.values()),
        "dynamic_requested": bool(dynamic),
        "dynamic_certified": None,
        "dynamic_error": None,
        "attestation": None,
    }

    if dynamic:
        if not result["static_certified"]:
            result["dynamic_certified"] = False
            result["dynamic_error"] = "static prerequisites failed"
        else:
            try:
                from .namespace_sandbox import NamespaceSandbox

                with tempfile.TemporaryDirectory(prefix="bull_certify_") as td:
                    sandbox = NamespaceSandbox(
                        seccomp_profile=seccomp_profile,
                        require_attestation=True,
                    )
                    probe = sandbox.run(
                        ["/usr/bin/true"],
                        project_root=td,
                        writable=False,
                        timeout=10.0,
                    )

                att = probe.attestation
                result["dynamic_certified"] = bool(
                    probe.returncode == 0
                    and att is not None
                    and att.pid == 1
                    and att.no_new_privs
                    and att.seccomp
                    and att.seccomp_profile == seccomp_profile
                    and att.network_isolated
                    and att.runtime_root == "/bull_runtime"
                )
                if att is not None:
                    result["attestation"] = {
                        "pid": att.pid,
                        "no_new_privs": att.no_new_privs,
                        "seccomp": att.seccomp,
                        "seccomp_profile": att.seccomp_profile,
                        "seccomp_rules": att.seccomp_rules,
                        "network_interfaces": list(att.network_interfaces),
                        "network_isolated": att.network_isolated,
                        "python": att.python,
                        "runtime_root": att.runtime_root,
                    }
                if not result["dynamic_certified"]:
                    result["dynamic_error"] = (
                        probe.stderr.strip()
                        or "backend attestation did not satisfy production requirements"
                    )
            except Exception as exc:
                result["dynamic_certified"] = False
                result["dynamic_error"] = f"{type(exc).__name__}: {exc}"

    result["certified"] = bool(
        result["static_certified"]
        and (
            not dynamic
            or result["dynamic_certified"] is True
        )
    )
    return result
