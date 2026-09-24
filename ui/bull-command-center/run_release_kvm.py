#!/usr/bin/env python3
"""Run BULL's real KVM integration using the published guest release.

If the pinned guest assets are absent, fetch and verify them first. This keeps
the dashboard one-click while preserving BULL's local-file/hash boundary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", choices=("all","allowed","denied","timeout","cancel","missing-protection"), default="all")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--asset-dir", type=Path, required=True)
    ap.add_argument("--cpu-profile", choices=("host","amd-native-ssbd"), default="host")
    args = ap.parse_args()

    asset_dir = args.asset_dir.expanduser().resolve()
    manifest = asset_dir / "assets-local.json"
    if not manifest.exists():
        install = subprocess.run(
            [sys.executable, str(HERE / "install_guest_assets.py"), "--output", str(asset_dir)],
            cwd=ROOT,
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            check=False,
        )
        if install.returncode != 0:
            return install.returncode

    data = json.loads(manifest.read_text("utf-8"))
    cmd = [
        sys.executable, "microvm/integration.py",
        "--case", args.case,
        "--output", str(args.output),
        "--cpu-profile", args.cpu_profile,
    ]
    for name in ("kernel","rootfs","firmware"):
        cmd += ["--" + name, data[name]["path"]]
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
        check=False,
    ).returncode

if __name__ == "__main__":
    raise SystemExit(main())
