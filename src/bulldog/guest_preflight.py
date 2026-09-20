"""Fail-closed guest dependency check, before admitting any workload.

This is a prerequisite check, never a dispatcher execution or KVM attestation.
Deployment gates remain mandatory in ProductionRuntime after this check.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time

from .namespace_sandbox import _run_bounded


UTILITY_OPTIONS = {
    "mount": ("--make-rprivate", "--rbind", "--make-rslave"),
    "unshare": ("--user", "--map-root-user", "--mount", "--pid", "--fork", "--net", "--ipc"),
    "chroot": (),
}


def _command(argv: list[str], timeout: float = 5) -> tuple[int, str, str]:
    # Fresh child group only; bounded output and deadline include failing utilities.
    return _run_bounded(argv, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                 "LANG": "C", "HOME": "/nonexistent"},
                        timeout=timeout, pass_fds=(), preexec_fn=None,
                        max_output_bytes=32768)


def inspect_guest() -> dict:
    started = time.monotonic()
    checks = {}

    def check(name, function):
        try:
            ok, detail = function()
            checks[name] = {"passed": bool(ok), "detail": detail}
        except Exception as exc:
            checks[name] = {"passed": False, "detail": f"{type(exc).__name__}: {exc}"}

    def utility(name, options):
        executable = shutil.which(name)
        if executable is None:
            return False, f"missing executable: {name}"
        rc, out, err = _command([executable, "--help"])
        missing = [option for option in options if option not in out + err]
        return rc == 0 and not missing, {"path": executable, "missing_options": missing, "returncode": rc}

    for name, options in UTILITY_OPTIONS.items():
        check(name, lambda name=name, options=options: utility(name, options))

    def bash():
        executable = shutil.which("bash")
        if executable is None:
            return False, "missing executable: bash (launcher requires pipefail)"
        rc, out, err = _command([executable, "--noprofile", "--norc", "-c",
                                "set -euo pipefail; a=(ok); test ${a[0]} = ok; ! (false | true)"])
        return rc == 0, {"path": executable, "returncode": rc, "stderr": err}
    check("bash_features", bash)

    def imports():
        rc, out, err = _command([sys.executable, "-I", "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import ssl,sqlite3,ctypes,fcntl,resource; "
            "import bulldog.profiles,bulldog.seccomp_policy,bulldog.landlock_policy",
            str(Path(__file__).resolve().parent.parent)])
        return rc == 0, {"returncode": rc, "stderr": err}
    check("production_imports", imports)

    def landlock():
        if platform.machine() != "x86_64":
            return False, "only x86-64 guest is supported"
        libc = ctypes.CDLL(None, use_errno=True)
        abi = int(libc.syscall(444, 0, 0, 1))  # read-only ABI query
        return abi >= 1, {"abi": abi, "errno": ctypes.get_errno() if abi < 0 else 0}
    check("guest_landlock_abi", landlock)

    def controllers():
        path = Path("/sys/fs/cgroup/cgroup.controllers")
        available = path.read_text().split()
        missing = sorted({"memory", "pids", "cpu"} - set(available))
        return not missing, {"available": available, "missing": missing}
    check("cgroup_v2_controllers", controllers)

    def scanner():
        if shutil.which("clamscan") is None:
            return False, "missing clamscan and usable offline signature database"
        from .malware_scanner import MalwareScanner
        with tempfile.TemporaryDirectory(prefix="bull-preflight-") as temporary:
            fixture = Path(temporary) / "clean.txt"
            fixture.write_text("BULL deterministic preflight fixture\n")
            scan = MalwareScanner().scan_file(fixture, timeout_seconds=30)
        return scan.clean, {"engine": scan.engine, "clean_fixture_scanned": scan.clean}
    check("scanner_functionality", scanner)

    # Only an actual sandbox launch can verify namespace and seccomp behavior;
    # executable names, kernel configuration and ABI queries are not sufficient.
    if all(checks[name]["passed"] for name in (*UTILITY_OPTIONS, "bash_features", "production_imports")):
        def backend():
            from .host_certify import certify_host
            result = certify_host(dynamic=True, seccomp_profile="strict")
            return result["certified"], result
        check("guest_strict_backend", backend)
    else:
        checks["guest_strict_backend"] = {"passed": False, "detail": "BLOCKED: prerequisite checks failed"}

    return {"status": "PASS" if all(c["passed"] for c in checks.values()) else "BLOCKED",
            "scope": "guest prerequisites only; no dispatched workload",
            "kernel": platform.release(), "checks": checks,
            "duration_ms": round((time.monotonic() - started) * 1000, 3)}


def main() -> int:
    report = inspect_guest()
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["status"] == "PASS" else 78


if __name__ == "__main__":
    raise SystemExit(main())
