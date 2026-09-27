#!/usr/bin/env python3
"""Create a public, hash-only handoff manifest for an independent BULL review."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CRITICAL = (
    "src/bulldog/profiles.py",
    "src/bulldog/dispatcher.py",
    "src/bulldog/production_router.py",
    "src/bulldog/effect_journal.py",
    "src/bulldog/namespace_sandbox.py",
    "src/bulldog/_namespace_launcher.sh",
    "src/bulldog/approval.py",
    "src/bulldog/hardware_approval/verifier.py",
    "deploy/egress_redirect.nft",
    "deploy/bull-egress-gateway.service",
    "tools/run_codespace_gateway_kvm.py",
    "tools/run_codespace_gateway_systemd_kvm.py",
    "tools/gateway_guest_probe.py",
    "formal/tla/BullRuntime.tla",
    "formal/refinement-map.json",
    "docs/HUMAN_FIRST_PRODUCTION_ASSURANCE.md",
)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents:
        parser.error("output must be a new path outside the repository")
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    ).strip()
    if dirty:
        parser.error("independent review manifest requires a clean source commit")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True
    ).strip()
    files = {name: sha(ROOT / name) for name in CRITICAL}
    value = {
        "format": "bull-independent-review-handoff-v1",
        "repository": "https://github.com/Anharmoniclabs/BULL",
        "source_commit": commit,
        "source_tree": tree,
        "critical_files_sha256": files,
        "required_reviewer_work": [
            "verify the clean source and guest image identities",
            "select attacks beyond the author test suite",
            "exercise ProductionEffectRouter and ProductionDispatcher paths",
            "attack writable mounts, broker peers, approval replay and audit outage",
            "repeat the combined bullagent/bullgw/systemd KVM candidate",
            "report failures and environmental blocks without converting them to passes",
        ],
        "excluded_private_material": [
            "disposable credentials",
            "private guest images",
            "raw case directories",
        ],
        "certification": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
