"""Small real-kernel resource probes; never run workloads as root.

At most 64 MiB of charged memory, eight fork attempts, and one second of
wall-clock CPU work. Every probe stays inside its own disposable scope.
"""
import os
from pathlib import Path
import subprocess
import sys

from bulldog.cgroup_scope import CgroupV2Scope


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
    assert blocked, 'pids limit did not reject bounded fork attempts'
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
                assert result.returncode == -9 and observed.get("oom_kill", 0) >= 1, (
                    f"memory limit evidence mismatch: returncode={result.returncode}, counters={observed}, "
                    f"probe_error={result.stderr.decode(errors='replace')[:512]}")
            elif name == "cpu":
                observed = counters(scope.path / "cpu.stat")
                assert result.returncode == 0 and observed.get("nr_throttled", 0) >= 1, "CPU quota was not enforced"
            else:
                observed = counters(scope.path / "pids.events")
                assert result.returncode == 0 and observed.get("max", 0) >= 1, "pids limit was not enforced"
            path = scope.path
        assert not path.exists(), "resource probe scope was not removed"
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
                try:
                    child.wait(timeout=0.2)
                    raise AssertionError("cleanup fixture exited unexpectedly")
                except subprocess.TimeoutExpired:
                    if reason == "timeout":
                        raise
                    raise InterruptedError("controlled cancellation")
        except (subprocess.TimeoutExpired, InterruptedError):
            pass
        finally:
            if child is not None:
                child.wait(timeout=5)
        assert path is not None and not path.exists(), "descendant scope cleanup failed"
        results[reason] = {"status": "PASS", "scope_removed": True}
    return results
