"""Small real-kernel resource probes; never run workloads as root.

At most 64 MiB of charged memory, eight fork attempts, and one second of
wall-clock CPU work. Every probe stays inside its own disposable scope.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from bulldog.cgroup_scope import CgroupV2Scope, CgroupUnavailable


def counters(path):
    return {k: int(v) for k, v in (line.split() for line in path.read_text().splitlines())}


def check_limits(parent):
    if os.geteuid() == 0:
        raise ValueError("resource probes must run as the normal operator, not root")
    results = {}
    for name, code in {
        "cpu": "import time\nend=time.monotonic()+1\nwhile time.monotonic()<end: pass",
        "memory": "x=bytearray(96*1024*1024)\nfor i in range(0,len(x),4096): x[i]=1",
        "pids": """import errno, os, signal, time
children=[]
blocked=False
try:
    for _ in range(8):
        try:
            pid=os.fork()
        except OSError as exc:
            if exc.errno != errno.EAGAIN: raise
            blocked=True
            break
        if pid == 0:
            time.sleep(5)
            os._exit(0)
        children.append(pid)
    if not blocked:
        raise RuntimeError('pids limit did not reject bounded fork attempts')
finally:
    for pid in children:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
""",
    }.items():
        with CgroupV2Scope(parent, memory_bytes=64*1024*1024, processes=4,
                           cpu_quota_us=25000) as scope:
            # No swap pressure on the operator's laptop.
            scope._write("memory.swap.max", "0")
            result = subprocess.run([sys.executable, "-I", "-c", code],
                                    preexec_fn=scope.attach_current, timeout=10,
                                    capture_output=True)
            if name == "memory":
                observed = counters(scope.path / "memory.events")
                if result.returncode != -9 or observed.get("oom_kill", 0) < 1:
                    raise RuntimeError(
                        f"memory limit evidence mismatch: returncode={result.returncode}, counters={observed}, "
                        f"probe_error={result.stderr.decode(errors='replace')[:512]}")
            elif name == "cpu":
                observed = counters(scope.path / "cpu.stat")
                if result.returncode != 0 or observed.get("nr_throttled", 0) < 1:
                    raise RuntimeError("CPU quota was not enforced")
            else:
                observed = counters(scope.path / "pids.events")
                if result.returncode != 0 or observed.get("max", 0) < 1:
                    raise RuntimeError("pids limit was not enforced")
            path = scope.path
        if path.exists():
            raise RuntimeError("resource probe scope was not removed")
        results[name] = {"status": "PASS", "returncode": result.returncode, "counters": observed}

    # Both an interrupted coordinator and a timeout must reap an owned process
    # tree. These fixture processes never execute user-supplied commands.
    for reason in ("cancel", "timeout"):
        child = None
        path = None
        try:
            with CgroupV2Scope(parent, memory_bytes=64*1024*1024, processes=4,
                               cpu_quota_us=25000) as scope:
                path = scope.path
                child = subprocess.Popen([sys.executable, "-I", "-c",
                    "import os,time; os.fork(); time.sleep(10)"],
                    preexec_fn=scope.attach_current)
                deadline = time.monotonic() + 2
                while len((path / "cgroup.procs").read_text().split()) < 2:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("cleanup fixture did not create its descendant")
                    time.sleep(0.01)
                try:
                    child.wait(timeout=0.2)
                    raise RuntimeError("cleanup fixture exited unexpectedly")
                except subprocess.TimeoutExpired:
                    if reason == "timeout":
                        raise
                    raise InterruptedError("controlled cancellation")
        except (subprocess.TimeoutExpired, InterruptedError):
            pass
        finally:
            if child is not None:
                child.wait(timeout=5)
        if path is None or path.exists():
            raise RuntimeError("descendant scope cleanup failed")
        results[reason] = {"status": "PASS", "scope_removed": True}

    # A real, owned cgroup with no controllers enabled must not admit work.
    undelegated = Path(tempfile.mkdtemp(prefix="bull-undelegated-", dir=parent))
    try:
        try:
            with CgroupV2Scope(undelegated, memory_bytes=64*1024*1024,
                               processes=4, cpu_quota_us=25000):
                raise RuntimeError("missing controllers admitted a scope")
        except CgroupUnavailable as exc:
            if "unable to configure cgroup" not in str(exc):
                raise
            results["missing_delegation"] = {"status": "PASS", "reason": str(exc)}
    finally:
        undelegated.rmdir()  # Also fails if partial scope setup leaked a child.
    return results
