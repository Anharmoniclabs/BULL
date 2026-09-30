#!/usr/bin/env python3
"""Tabulate qualification evidence and publish bounded reports, never credentials.

This tool uses only the standard library, so installation failures can be reported.
Raw logs, ledgers, private keys, gateway configuration and SQLite state stay local.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

PIN = "6648bd0c290efbc41ba131ee9831ee45cd431f94"
BINARIES = (
    "target/release/openshell", "target/release/openshell-gateway",
    "target/release/openshell-supervisor",
    "target/x86_64-unknown-linux-musl/release/openshell-sandbox",
)
OPEN = (
    ("Native OCSF identity export", "Native exporter and exact 10,000-request join not implemented"),
    ("Transport/sandbox authentication", "Authenticated channel and sandbox identity binding not qualified"),
    ("Distributed revocation", "Only the adapter's local authority graph is covered"),
    ("Emergency termination/credentials", "Real process termination and credential invalidation not qualified"),
    ("Multi-process audit scaling", "Scaling harness covers a persistent single writer"),
    ("Crash/storage recovery campaign", "Regression coverage is not a full host fault campaign"),
    ("Hung-worker recovery/failover", "Deadlines/capacity are tested; automated recovery remains open"),
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def read_json(path):
    try:
        if path.is_symlink():
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def initialize(root, out, quick):
    info = {"format": "bull-codespaces-qualification-v1",
            "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "source": git(root, "rev-parse", "HEAD"),
            "source_tree": git(root, "rev-parse", "HEAD^{tree}"),
            "working_tree_modified": bool(git(root, "status", "--porcelain")),
            "python": platform.python_version(), "kernel": platform.release(),
            "quick": quick, "pinned_openshell": PIN}
    write_json(out / "run-info.json", info)
    (out / "stage-exit-codes.tsv").write_text("")
    print("Source:", info["source"], "| Evidence:", out, flush=True)


def preflight(out, source):
    src = Path(source) if source else None
    missing = []
    if src is None:
        missing.append("built OpenShell source; use --os-src /absolute/path/to/OpenShell")
    else:
        missing.extend(p for p in BINARIES if not (src / p).is_file() or not os.access(src / p, os.X_OK))
    actual = None
    if src is not None:
        try:
            actual = git(src, "rev-parse", "HEAD")
            if actual != PIN:
                missing.append("OpenShell must be at pinned commit " + PIN)
            if git(src, "diff", "HEAD", "--"):
                missing.append("OpenShell tracked build inputs differ from pinned source")
        except subprocess.CalledProcessError:
            missing.append("OpenShell source is not a Git checkout")
    if not shutil.which("docker"):
        missing.append("docker executable")
    else:
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
            if result.returncode:
                missing.append("reachable Docker daemon (check docker info)")
        except (OSError, subprocess.TimeoutExpired):
            missing.append("reachable Docker daemon (check docker info)")
    report = {"status": "BLOCKED" if missing else "PASS", "missing": missing,
              "openshell_source": str(src) if src else None, "openshell_commit": actual,
              "expected_commit": PIN,
              "scope": "Host prerequisites; does not attest binary reproducibility"}
    write_json(out / "native-preflight.json", report)
    for item in missing:
        print("Native prerequisite:", item)
    print("Native preflight:", report["status"], flush=True)
    return 2 if missing else 0


def finalize(out, runner_exit):
    info = read_json(out / "run-info.json")
    codes = {}
    for line in (out / "stage-exit-codes.tsv").read_text().splitlines():
        name, code = line.split("\t")
        codes[name] = int(code)
    rows = []

    def row(name, status, detail):
        rows.append({"check": name, "status": status, "detail": detail})

    setup_ok = codes.get("setup-venv") == 0 and codes.get("setup-install") == 0
    row("Python/dependencies", "PASS" if setup_ok else "FAIL", "See setup-venv.log and setup-install.log")
    cases = []
    try:
        cases = list(ET.parse(out / "regression.xml").getroot().iter("testcase"))
    except (OSError, ET.ParseError):
        pass
    failed = sum(c.find("failure") is not None or c.find("error") is not None for c in cases)
    skipped = sum(c.find("skipped") is not None for c in cases)
    passed = len(cases) - failed - skipped
    reg_status = "PASS" if codes.get("regression") == 0 and cases and failed == 0 else ("FAIL" if "regression" in codes else "NOT_RUN")
    row("Full regression", reg_status, f"{passed} passed, {failed} failed, {skipped} skipped; regression.log")
    report = read_json(out / "loopback/report.json")
    faults = report.get("faults", {})
    fault_cases = faults.get("cases", [])
    fault_ok = bool(fault_cases) and faults.get("passed") is True and all(c.get("pass") is True for c in fault_cases)
    loop_status = "FAIL" if "loopback" in codes else "NOT_RUN"
    row("gRPC/HTTP fault cases", "PASS" if codes.get("loopback") == 0 and fault_ok else loop_status,
        f"{sum(c.get('pass') is True for c in fault_cases)}/{len(fault_cases)}; loopback fixture, not native OpenShell")
    concurrent = report.get("concurrency", {})
    exact = concurrent.get("correlation", {}).get("exact") is True
    verified = concurrent.get("ledger_verification", {}).get("valid") is True
    workload_ok = exact and verified and concurrent.get("requests") == 10000 and concurrent.get("effects") == 10000
    row("10,000-request attribution", "PASS" if codes.get("loopback") == 0 and workload_ok else loop_status,
        f"{concurrent.get('effects', '?')}/{concurrent.get('requests', '?')} effects; exact={exact}; contract fixture")
    scale = report.get("scaling", {})
    if info.get("quick"):
        row("Million-record audit scaling", "NOT_RUN", "Explicitly skipped by --quick")
    else:
        scale_verify = scale.get("final_verification", {})
        scale_ok = scale_verify.get("valid") is True and scale_verify.get("records") == 1000000
        row("Million-record audit scaling", "PASS" if codes.get("loopback") == 0 and scale_ok else loop_status,
            f"{scale_verify.get('records', '?')} verified records; persistent single writer")
    native_preflight = read_json(out / "native-preflight.json")
    native_blocked = native_preflight.get("status") == "BLOCKED" and codes.get("native-preflight") == 2
    if native_blocked:
        row("Native prerequisites", "BLOCKED", "; ".join(native_preflight.get("missing", [])))
    else:
        row("Native prerequisites", "PASS" if codes.get("native-preflight") == 0 else "NOT_RUN", "See native-preflight.json")
    native = read_json(out / "native/report.json")
    native_cases = native.get("cases", [])
    native_ok = native.get("status") == "PASS" and len(native_cases) == 11 and all(c.get("pass") is True for c in native_cases)
    row("Native faults/restart/revocation", "PASS" if codes.get("native_faults") == 0 and native_ok else
        ("BLOCKED" if native_blocked else ("FAIL" if "native_faults" in codes else "NOT_RUN")),
        f"{sum(c.get('pass') is True for c in native_cases)}/{len(native_cases)} native cases")
    composition = read_json(out / "composition/results.json")
    ab_cases = composition.get("results", [])
    ab_ok = bool(ab_cases) and all(c.get("pass") is True for c in ab_cases) and {c.get("phase") for c in ab_cases} == {"A-openshell-only", "B-openshell+bull"}
    row("Native A/B composition", "PASS" if codes.get("native_composition") == 0 and ab_ok else
        ("BLOCKED" if native_blocked else ("FAIL" if "native_composition" in codes else "NOT_RUN")),
        f"{sum(c.get('pass') is True for c in ab_cases)}/{len(ab_cases)} native A/B cases")
    for name, detail in OPEN:
        row(name, "OPEN", detail)
    required_not_run = any(r["status"] == "NOT_RUN" and r["check"] != "Million-record audit scaling" for r in rows)
    bad = runner_exit != 0 or required_not_run or any(r["status"] == "FAIL" for r in rows)
    result = 1 if bad else (2 if native_blocked else 0)
    summary = {**info, "finished_utc": datetime.now(timezone.utc).isoformat(), "exit_codes": codes,
               "runner_exit": runner_exit, "qualification_exit": result,
               "status": "FAIL" if bad else ("BLOCKED" if native_blocked else "PASS_TESTED_SCOPE"),
               "regression_counts": {"passed": passed, "failed": failed, "skipped": skipped},
               "checks": rows, "raw_evidence_directory": str(out)}
    write_json(out / "summary.json", summary)
    raw_manifest = []
    raw_names = ["regression.xml", *[name + ".log" for name in codes],
                 "loopback/fault-ledger.jsonl", "loopback/concurrency-ledger.jsonl",
                 "loopback/scaling-ledger.jsonl", "loopback/contract-layer-events.jsonl",
                 "loopback/destination-receipts.jsonl", "loopback/exact-correlation.json",
                 "native/bull-audit.jsonl", "composition/bull-audit.jsonl"]
    for name in raw_names:
        path = out / name
        if path.is_file() and not path.is_symlink():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            raw_manifest.append({"path": name, "bytes": path.stat().st_size, "sha256": digest.hexdigest()})
    write_json(out / "local-evidence-manifest.json", {"files": raw_manifest, "scope": "Hashes only; raw evidence retained on test host"})
    with (out / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, ["check", "status", "detail"])
        writer.writeheader()
        writer.writerows(rows)
    table = "| Check | Status | Evidence / boundary |\n| --- | --- | --- |\n"
    for r in rows:
        table += "| " + " | ".join(str(r[k]).replace("|", "/").replace("\n", " ") for k in ("check", "status", "detail")) + " |\n"
    (out / "SUMMARY.md").write_text(f"# BULL Codespaces qualification\n\nSource: `{info.get('source')}`\n\nOverall: **{summary['status']}**\n\n" + table + "\nPASS_TESTED_SCOPE leaves the OPEN boundaries unqualified. Raw logs and credentials remain on the test host.\n")
    print("\n" + table, end="")
    print("Overall:", summary["status"], "| Exit:", result, flush=True)
    return result


def export_evidence(out, target):
    """Explicit report allowlist: never recursively copy test output directories."""
    paths = ("run-info.json", "summary.json", "summary.csv", "SUMMARY.md", "stage-exit-codes.tsv",
             "native-preflight.json", "local-evidence-manifest.json", "loopback/report.json",
             "native/report.json", "composition/cases.csv", "composition/latency.csv")
    manifest = []
    for name in paths:
        src = out / name
        if not src.is_file() or src.is_symlink():
            continue
        data = src.read_bytes()
        if len(data) > 2_000_000:
            raise ValueError("Compact evidence exceeds limit: " + name)
        dest = target / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        manifest.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    exact = read_json(out / "loopback/exact-correlation.json")
    if exact:
        dest = target / "loopback/exact-correlation.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        write_json(dest, {"summary": exact.get("summary", {}), "row_count": len(exact.get("rows", [])),
                          "scope": "Compact summary; full join rows and their hash retained in local evidence"})
        data = dest.read_bytes()
        manifest.append({"path": "loopback/exact-correlation.json", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    # Retain numeric composition results without gateway-info/config metadata.
    ab = read_json(out / "composition/results.json")
    if ab:
        selected = {k: ab[k] for k in ("format", "openshell", "host", "results", "latency_summary") if k in ab}
        dest = target / "composition/results.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        write_json(dest, selected)
        data = dest.read_bytes()
        manifest.append({"path": "composition/results.json", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    write_json(target / "manifest.json", {"files": manifest, "scope": "Compact qualification reports; raw logs/keys/state excluded"})


def publish(root, out):
    summary = read_json(out / "summary.json")
    if not summary:
        raise ValueError("Finalize results before publishing")
    if summary.get("working_tree_modified"):
        raise ValueError("Evidence publishing requires a clean source checkout to bind results to the tested commit")
    if git(root, "rev-parse", "HEAD") != summary["source"] or git(root, "status", "--porcelain"):
        raise ValueError("Source checkout changed during qualification; evidence remains local")
    # Inspect the configured URL rather than Git's expanded insteadOf URL. This
    # supports credential helpers and local transport fixtures without printing secrets.
    pushurl = subprocess.run(["git", "-C", str(root), "config", "--get", "remote.origin.pushurl"], capture_output=True, text=True)
    remote = pushurl.stdout.strip() if pushurl.returncode == 0 else git(root, "config", "--get", "remote.origin.url")
    if remote not in ("https://github.com/Anharmoniclabs/BULL.git", "https://github.com/Anharmoniclabs/BULL",
                      "git@github.com:Anharmoniclabs/BULL.git", "ssh://git@github.com/Anharmoniclabs/BULL.git"):
        raise ValueError("origin must point to Anharmoniclabs/BULL for results publication")
    branch = "results/openshell-" + summary["run_id"]
    # A separate worktree means no checkout/staging of the operator's current work.
    work = Path(tempfile.mkdtemp(prefix="bull-results-publish-"))
    state = {"branch": branch, "source": summary["source"], "worktree": str(work), "status": "PREPARING"}
    write_json(out / "publication.json", state)
    subprocess.run(["git", "-C", str(root), "worktree", "add", "-b", branch, str(work), summary["source"]], check=True)
    try:
        relative = "docs/evidence/codespaces/" + summary["run_id"]
        target = work / relative
        target.mkdir(parents=True)
        export_evidence(out, target)
        subprocess.run(["git", "-C", str(work), "add", "--", relative], check=True)
        # Use repository identity if configured; otherwise name the automation.
        cmd = ["git", "-C", str(work)]
        for key, fallback in (("user.name", "BULL qualification runner"), ("user.email", "bull-qualification@users.noreply.github.com")):
            if subprocess.run(cmd + ["config", "--get", key], stdout=subprocess.DEVNULL).returncode:
                cmd += ["-c", key + "=" + fallback]
        subprocess.run(cmd + ["commit", "-m", "Record Codespaces OpenShell qualification: " + summary["status"]], check=True)
        state.update(status="COMMITTED", commit=git(work, "rev-parse", "HEAD"))
        write_json(out / "publication.json", state)
        subprocess.run(["git", "-C", str(work), "push", "origin", "HEAD:refs/heads/" + branch], check=True)
        state.update(status="PUSHED", url="https://github.com/Anharmoniclabs/BULL/tree/" + branch + "/" + relative)
        write_json(out / "publication.json", state)
        print("Results pushed:", state["url"], flush=True)
    except Exception:
        state["status"] = "PUBLISH_FAILED"
        write_json(out / "publication.json", state)
        print("Results remain local. Retry after fixing GitHub write authentication:")
        print(f"git -C '{work}' push origin HEAD:refs/heads/{branch}", flush=True)
        raise
    else:
        subprocess.run(["git", "-C", str(root), "worktree", "remove", str(work)], check=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "finalize", "publish", "preflight"):
        sub = commands.add_parser(name)
        sub.add_argument("--output", type=Path, required=True)
        if name in ("init", "publish"):
            sub.add_argument("--root", type=Path, required=True)
        if name == "init":
            sub.add_argument("--quick", action="store_true")
        if name == "finalize":
            sub.add_argument("--runner-exit", type=int, default=0)
        if name == "preflight":
            sub.add_argument("--os-src", default="")
    args = parser.parse_args()
    if args.command == "init":
        initialize(args.root, args.output, args.quick)
        return 0
    if args.command == "finalize":
        return finalize(args.output, args.runner_exit)
    if args.command == "preflight":
        return preflight(args.output, args.os_src)
    return publish(args.root, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
