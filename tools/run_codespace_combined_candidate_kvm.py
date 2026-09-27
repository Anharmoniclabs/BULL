#!/usr/bin/env python3
"""Run the networked bullagent + bullgw + nftables + systemd KVM candidate.

This builds a fresh direct-init lab, then clones it into the final systemd
candidate. It does not modify or relabel the pinned offline production image.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    process = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=5400,
    )
    print(process.stdout, end="", flush=True)
    match = re.search(
        r"(?m)^Evidence directory: (/tmp/bull-[A-Za-z0-9_-]+)$", process.stdout
    )
    if process.returncode or not match:
        raise RuntimeError(
            "candidate stage failed; preserve the printed private report"
        )
    return Path(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-deps", action="store_true")
    args = parser.parse_args()
    try:
        gateway_command = [sys.executable, "tools/run_codespace_gateway_kvm.py"]
        if args.install_deps:
            gateway_command.append("--install-deps")
        lab = run(gateway_command)
        candidate = run(
            [
                sys.executable,
                "tools/run_codespace_gateway_systemd_kvm.py",
                "--from-lab",
                str(lab),
            ]
        )
        report = json.loads((candidate / "setup-report.json").read_text())
        checks = report.get("guest_result", {}).get("checks", {})
        required = {
            "agent_workload_uid",
            "gateway_uid",
            "service_units_active",
            "allowed_http",
            "denied_http",
            "denied_dns",
            "ipv4_alt_closed",
            "ipv6_alt_closed",
            "ipv6_web_closed",
            "gateway_down_closed",
            "restart_still_denies",
            "filter_drop_counters",
            "direct_gateway_http",
        }
        if (
            report.get("status") != "PASS"
            or set(checks) != required
            or any(value is not True for value in checks.values())
        ):
            raise RuntimeError("final candidate report incomplete")
        summary = {
            "status": "CANDIDATE PASS",
            "checks": len(checks),
            "source_commit": report["source_commit"],
            "scope": "disposable Debian KVM candidate with bullagent, bullgw, nftables and systemd",
            "remaining": "ProductionEffectRouter/ProductionDispatcher workload path and pinned image release are separate gates",
            "systemd_candidate_directory": str(candidate),
            "direct_init_lab_directory": str(lab),
        }
        print(json.dumps(summary))
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        print("BLOCKED/FAIL:", str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
