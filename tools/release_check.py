#!/usr/bin/env python3
"""Collect source validation evidence; never equate it with certification.

Run on a supported Linux host. All logs remain in the new output directory.
Missing tools, failures and skipped tests prevent a source-gate PASS.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
TLA_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tla-jar", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("write private evidence outside the repository")
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    def run(name, argv, timeout=300):
        started = time.monotonic()
        try:
            with (out / (name + ".log")).open("w") as log:
                result = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=timeout, check=False,
                                        env={k: v for k, v in os.environ.items() if not k.startswith("BULL_")})
            status, code = ("PASS" if result.returncode == 0 else "FAIL"), result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            (out / (name + ".log")).write_text(type(exc).__name__ + ": " + str(exc))
            status, code = "BLOCKED", None
        results.append({"gate": name, "status": status, "returncode": code,
                        "seconds": round(time.monotonic() - started, 3)})
        print(name + ": " + status, flush=True)
    def git(*argv):
        return subprocess.check_output(["git", *argv], cwd=ROOT, text=True).strip()
    sha = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    paths = git("ls-files").splitlines()
    source_digest = hashlib.sha256()
    for name in sorted(paths):
        path = ROOT / name
        if path.is_file() and not path.is_symlink():
            source_digest.update(name.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    run("diff-check", ["git", "diff", "--check"])
    run("compile", [sys.executable, "-m", "compileall", "-q", "src/bulldog"])
    run("pytest", [sys.executable, "-m", "pytest", "-q", "--junitxml=" + str(out / "pytest.xml")])
    counts = {}
    if (out / "pytest.xml").exists():
        suites = ET.parse(out / "pytest.xml").getroot()
        for key in ("tests", "failures", "errors", "skipped"):
            counts[key] = sum(int(x.get(key, 0)) for x in suites.iter("testsuite"))
        if counts.get("skipped", 0):
            results.append({"gate": "no-skipped-tests", "status": "FAIL"})
    else:
        results.append({"gate": "test-results", "status": "BLOCKED"})
    jar = args.tla_jar.resolve()
    if not jar.is_file() or hashlib.sha256(jar.read_bytes()).hexdigest() != TLA_SHA256:
        results.append({"gate": "formal-tool-integrity", "status": "BLOCKED"})
    else:
        for model in ("BullRuntime", "BullSessionAudit", "BullApproval"):
            run(model + "-parse", ["java", "-cp", str(jar), "tla2sany.SANY", f"formal/tla/{model}.tla"])
            run(model + "-model", ["java", "-cp", str(jar), "tlc2.TLC", "-deadlock", "-workers", "1",
                "-metadir", str(out / (model + "-states")), "-config", f"formal/tla/{model}.cfg", f"formal/tla/{model}.tla"])
    run("wheel", [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", ".", "-w", str(out / "wheel")])
    run("distribution", [sys.executable, "tools/check_package.py", "--output", str(out / "distribution")])
    run("site", [sys.executable, "tools/build_site.py", "--output", str(out / "site")])
    results.append({"gate": "unchanged-clean-source", "status": "PASS" if
                    not dirty and git("rev-parse", "HEAD") == sha and
                    not git("status", "--porcelain") else "FAIL"})
    source_pass = all(x["status"] == "PASS" for x in results)
    report = {"format": "bull-source-evidence-v1", "commit": sha, "dirty": dirty,
              "tracked_content_sha256": source_digest.hexdigest(), "python": platform.python_version(),
              "platform": platform.platform(), "gates": results, "pytest_counts": counts,
              "source_checks_passed": source_pass, "certified": False,
              "deployment_gates": {"real_hardware_approval": "NOT_RUN", "current_candidate_kvm": "NOT_RUN",
                  "external_collector_with_guest": "NOT_RUN", "independent_review": "NOT_RUN"},
              "scope": "Source checks only; no universal security or physical-presence claim."}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Report: " + str(out / "report.json"))
    return 0 if source_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
