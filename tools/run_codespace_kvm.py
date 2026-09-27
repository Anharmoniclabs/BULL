#!/usr/bin/env python3
"""Prepare a pinned guest and run BULL's five real-KVM cases, or report why blocked.

Usage: python3 tools/run_codespace_kvm.py [--install-deps] [--assets /absolute/manifest.json]
The output directory is private and outside the checkout. Never upload it whole.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from tools.deployment_check import checked_assets, probe_kvm, source_identity
from bulldog.release_evidence import read_checksums

RELEASE = "guest-2026-09-22"
FILES = ("bzImage", "rootfs.ext4", "qboot.rom", "assets.json", "build.json",
         "SHA256SUMS", "RELEASE_SCOPE.txt")
NEEDED = ("qemu-system-x86_64", "openssl", "mkfs.ext4", "debugfs")


def write_report(directory: Path, report: dict) -> None:
    path = directory / "setup-report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)
    print("Setup report:", path, flush=True)


def obtain_assets(directory: Path) -> Path:
    if not shutil.which("gh"):
        raise RuntimeError("GitHub CLI missing; install gh or pass --assets with a verified local manifest")
    release = directory / "release"
    release.mkdir(mode=0o700)
    command = ["gh", "release", "download", RELEASE, "--repo", "Anharmoniclabs/BULL",
               "--dir", str(release)]
    for filename in FILES:
        command += ["--pattern", filename]
    subprocess.run(command, check=True)
    if any(not (release / filename).is_file() for filename in FILES):
        raise RuntimeError("release is missing one of the required image, manifest or checksum files")
    expected = read_checksums(release / "SHA256SUMS")
    images = {"bzImage", "rootfs.ext4", "qboot.rom"}
    if not images <= set(expected):
        raise RuntimeError("image release checksums missing: " + ", ".join(sorted(images - set(expected))))
    # Older guest releases cover the VM images but may omit release metadata.
    # Verify all downloaded files that do have entries; the image hashes are
    # mandatory, and assets.json must independently agree with each image.
    for filename, sha in expected.items():
        if filename not in FILES:
            continue
        with (release / filename).open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != sha:
            raise RuntimeError("release SHA-256 mismatch: " + filename)
    upstream = json.loads((release / "assets.json").read_text())
    if set(upstream) != {"kernel", "rootfs", "firmware"}:
        raise RuntimeError("unexpected release manifest schema")
    mapping = {"kernel": "bzImage", "rootfs": "rootfs.ext4", "firmware": "qboot.rom"}
    local = {key: {"path": str(release / filename), "sha256": upstream[key]["sha256"]}
             for key, filename in mapping.items()}
    manifest = release / "assets-local.json"
    manifest.write_text(json.dumps(local, indent=2) + "\n")
    manifest.chmod(0o600)
    checked_assets(manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, help="absolute local manifest of SHA-256-pinned guest images")
    parser.add_argument("--install-deps", action="store_true", help="install missing Debian VM tools with sudo apt-get")
    parser.add_argument("--offline-egress", action="store_true", help="prove the pinned guest workload has no outward network path")
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="bull-kvm-", dir="/tmp"))
    source = source_identity()
    report = {"status": "BLOCKED", "source_commit": source["commit"],
              "source_dirty": source["dirty"], "kvm": probe_kvm(), "evidence_directory": str(directory)}
    print("Evidence directory:", directory, flush=True)
    try:
        if source["dirty"]:
            raise RuntimeError("checkout has local changes; use a clean integration commit for source-bound evidence")
        if report["kvm"]["status"] != "PASS":
            raise RuntimeError("KVM device/API unavailable: " + report["kvm"].get("reason", "unknown"))
        manifest = args.assets.resolve() if args.assets else obtain_assets(directory)
        assets = checked_assets(manifest)
        report["asset_sha256"] = {key: item["sha256"] for key, item in assets.items()}
        missing = [tool for tool in NEEDED if not shutil.which(tool)]
        if missing and args.install_deps:
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "qemu-system-x86", "e2fsprogs", "openssl"], check=True)
            missing = [tool for tool in NEEDED if not shutil.which(tool)]
        if missing:
            raise RuntimeError("missing VM tools: " + ", ".join(missing) + "; retry with --install-deps")
        output = directory / ("offline-egress" if args.offline_egress else "cases")
        command = [sys.executable, "microvm/integration.py", "--case",
                   "offline-egress" if args.offline_egress else "all", "--output", str(output)]
        for key, item in assets.items():
            command += ["--" + key, item["path"]]
        result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")), check=False)
        if args.offline_egress:
            evidence = json.loads((output / "report.json").read_text())
            if (result.returncode or evidence.get("status") != "PASS"
                    or evidence.get("case") != "offline-egress"
                    or evidence.get("revision") != source["commit"]
                    or evidence.get("assets") != report["asset_sha256"]
                    or evidence.get("qemu_network") != "none (observed child command line)"
                    or evidence.get("offline_egress", {}).get("interfaces") != ["lo"]
                    or set(evidence.get("offline_egress", {}).get("denials", {})) != {"ipv4", "ipv6"}):
                raise RuntimeError("offline egress KVM case incomplete or failed; inspect private report")
            if source_identity() != source:
                raise RuntimeError("source changed during evidence run")
            report["status"] = "PASS"
            report["offline_egress_report"] = str(output / "report.json")
            print("Offline guest workload egress PASS; QEMU -net none observed. Gateway service is unverified.")
            return 0
        summary = output / "summary.json"
        if not summary.is_file():
            raise RuntimeError(f"five-case runner exited {result.returncode} without a summary")
        cases = json.loads(summary.read_text())
        expected = {"allowed", "denied", "timeout", "cancel", "missing-protection"}
        if result.returncode or cases.get("status") != "PASS" or set(cases.get("cases", {})) != expected or any(cases["cases"][key] != "PASS" for key in expected):
            raise RuntimeError("five-case run incomplete or failed; inspect private cases/summary.json")
        for key in expected:
            evidence = json.loads((output / key / "report.json").read_text())
            if evidence.get("revision") != source["commit"] or evidence.get("assets") != report["asset_sha256"]:
                raise RuntimeError("case source or asset identity mismatch: " + key)
        if source_identity() != source:
            raise RuntimeError("source changed during evidence run")
        report["status"] = "PASS"
        report["summary"] = str(summary)
        print("Five real-KVM cases PASS. Review and share summary, setup report and redacted case reports.")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as exc:
        report["reason"] = str(exc)
        print("BLOCKED/FAIL:", exc, file=sys.stderr)
        return 1
    finally:
        write_report(directory, report)
        print("Keep the private evidence directory local; case files include disposable credentials.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
