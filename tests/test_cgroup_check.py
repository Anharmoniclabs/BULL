"""Validation logic under real optimized interpreters; no isolation claims from mocks."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Each interpreter receives known-good fixture evidence except for one selected
# failure. Exercise check_limits itself, including both return codes and counters.
FIXTURE = r'''
import json, shutil, subprocess, sys, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path[:0] = [sys.argv[1], str(Path(sys.argv[1]) / "src")]
from tools import cgroup_check as check
failure = sys.argv[2]
expected = sys.argv[3]
index = -1

class Scope:
    def __init__(self, parent, **kwargs):
        self.parent = Path(parent)
    def __enter__(self):
        global index
        if self.parent.name.startswith("bull-undelegated-"):
            raise check.CgroupUnavailable("unable to configure cgroup memory.max: fixture")
        index += 1
        self.path = self.parent / str(index)
        self.path.mkdir()
        (self.path / "cgroup.procs").write_text("1\n2\n")
        return self
    def _write(self, *args):
        pass
    def attach_current(self):
        pass
    def __exit__(self, *args):
        if not ((failure == "scope-cleanup" and index == 0)
                or (failure == "descendant-cleanup" and index == 3)):
            shutil.rmtree(self.path)

class Child:
    def __init__(self, *args, **kwargs):
        pass
    def wait(self, timeout):
        if timeout == 0.2:
            raise subprocess.TimeoutExpired("fixture", timeout)
        return -9

def run(*args, **kwargs):
    code = -9 if index == 1 else 0
    if failure == ("cpu-code", "memory-code", "pids-code")[index]:
        code = 1
    return subprocess.CompletedProcess(args, code, b"", b"")

def counters(path):
    value = 0 if failure == ("cpu-counter", "memory-counter", "pids-counter")[index] else 1
    return {"nr_throttled": value, "oom_kill": value, "max": value}

with tempfile.TemporaryDirectory() as directory:
    with patch.object(check, "CgroupV2Scope", Scope), patch.object(check.os, "geteuid", return_value=1000), \
         patch.object(check.subprocess, "run", run), patch.object(check.subprocess, "Popen", Child), \
         patch.object(check, "counters", counters):
        try:
            result = check.check_limits(Path(directory))
        except RuntimeError as exc:
            if failure == "none" or expected not in str(exc):
                raise
            print("EXPECTED_FAILURE:" + str(exc))
        else:
            if failure != "none":
                raise SystemExit("invalid enforcement evidence was accepted")
            if len(result) != 6 or any(v["status"] != "PASS" for v in result.values()):
                raise SystemExit("incomplete fixture control result")
            print("CONTROL_PASS")
'''


@pytest.mark.parametrize("mode", ["normal", "-O", "-OO", "PYTHONOPTIMIZE"])
@pytest.mark.parametrize("failure,expected", [
    ("cpu-code", "CPU quota"), ("cpu-counter", "CPU quota"),
    ("memory-code", "memory limit evidence"), ("memory-counter", "memory limit evidence"),
    ("pids-code", "pids limit"), ("pids-counter", "pids limit"),
    ("scope-cleanup", "resource probe scope"), ("descendant-cleanup", "descendant scope"),
    ("none", ""),
])
def test_enforcement_failures_survive_optimization(mode, failure, expected):
    env = {k: v for k, v in os.environ.items() if not k.startswith("BULL_")}
    env.pop("PYTHONOPTIMIZE", None)
    flags = [] if mode in {"normal", "PYTHONOPTIMIZE"} else [mode]
    if mode == "PYTHONOPTIMIZE":
        env["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run([sys.executable, *flags, "-c", FIXTURE, str(ROOT), failure, expected],
                            env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("CONTROL_PASS" if failure == "none" else "EXPECTED_FAILURE:") in result.stdout
