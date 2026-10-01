#!/usr/bin/env python3
"""Run a source-bound long-duration qualification probe and checkpoint evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def source():
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    )
    return commit, dirty


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--max-hours", type=float, default=24)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="trusted probe command after --; agent input must never construct this",
    )
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command or not 1 <= args.iterations <= 1_000_000:
        parser.error("a trusted command and 1..1000000 iterations are required")
    if not 0 < args.timeout <= 3600 or not 0 < args.max_hours <= 24 * 31:
        parser.error("timeout/max-hours outside bounded campaign limits")
    output = args.output.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents:
        parser.error("output must be a new directory outside the repository")
    output.mkdir(mode=0o700, parents=True)
    commit, dirty = source()
    if dirty:
        parser.error("assurance campaign requires a clean source revision")
    started = time.time()
    records = output / "iterations.jsonl"
    interrupted = False

    def stop(_sig, _frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    passed = failed = 0
    with records.open("x", encoding="utf-8") as stream:
        os.chmod(records, 0o600)
        for index in range(args.iterations):
            if interrupted or time.time() - started >= args.max_hours * 3600:
                break
            before = time.monotonic()
            try:
                result = subprocess.run(
                    args.command,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=args.timeout,
                    check=False,
                )
                ok = result.returncode == 0
                record = {
                    "iteration": index,
                    "status": "PASS" if ok else "FAIL",
                    "returncode": result.returncode,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "elapsed_seconds": round(time.monotonic() - before, 6),
                }
            except subprocess.TimeoutExpired as exc:
                ok = False
                record = {
                    "iteration": index,
                    "status": "FAIL",
                    "reason": "timeout",
                    "stdout_sha256": hashlib.sha256(exc.stdout or b"").hexdigest(),
                    "stderr_sha256": hashlib.sha256(exc.stderr or b"").hexdigest(),
                    "elapsed_seconds": round(time.monotonic() - before, 6),
                }
            passed += int(ok)
            failed += int(not ok)
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    completed = passed + failed
    upper = None if failed or completed == 0 else 1 - math.pow(0.05, 1 / completed)
    final_commit, final_dirty = source()
    status = (
        "PASS"
        if completed == args.iterations
        and failed == 0
        and final_commit == commit
        and not final_dirty
        else "INCOMPLETE_OR_FAIL"
    )
    report = {
        "format": "bull-assurance-campaign-v1",
        "status": status,
        "source_commit": commit,
        "source_unchanged": final_commit == commit and not final_dirty,
        "command_sha256": hashlib.sha256(json.dumps(args.command).encode()).hexdigest(),
        "requested_iterations": args.iterations,
        "completed_iterations": completed,
        "passed": passed,
        "failed": failed,
        "elapsed_seconds": round(time.time() - started, 3),
        "zero_failure_upper_95": upper,
        "statistical_scope": (
            "One-sided exact binomial bound, only if trials are representative and "
            "independent; it is not a universal escape probability."
        ),
        "interrupted": interrupted,
    }
    path = output / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    print(json.dumps(report))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
