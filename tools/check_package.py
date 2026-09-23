#!/usr/bin/env python3
"""Build the committed source distribution and exercise its wheel in a fresh venv."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("use a new output directory outside the checkout")
    out.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items()
           if k not in {"PYTHONPATH", "PYTHONHOME"} and not k.startswith("BULL_")}

    def run(*command, cwd=out):
        subprocess.run(command, cwd=cwd, env=env, check=True)

    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    # Only committed files enter the build. Local credentials and stale build
    # outputs cannot be swept into a release by setuptools file discovery.
    archive = out / "BULL-source.tar"
    run("git", "archive", "--format=tar", "-o", str(archive), commit, cwd=ROOT)
    source = out / "source"
    source.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(source, filter="data")
    artifacts = out / "artifacts"
    # The build frontend builds the wheel FROM the newly built sdist by default.
    run(sys.executable, "-m", "build", "--no-isolation", "--outdir", str(artifacts), cwd=source)
    wheels = list(artifacts.glob("*.whl"))
    sdists = list(artifacts.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError("expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        metadata = wheel.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode()
        for required in ("License-Expression: GPL-2.0-or-later", "License-File: LICENSE",
                         "License-File: THIRD_PARTY_NOTICES.md"):
            if required not in metadata:
                raise RuntimeError("missing package metadata: " + required)
        for suffix in ("/licenses/LICENSE", "/licenses/THIRD_PARTY_NOTICES.md",
                       "bulldog/_namespace_launcher.sh"):
            if not any(name.endswith(suffix) for name in names):
                raise RuntimeError("missing wheel material: " + suffix)
    environment = out / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = str(environment / "bin/python")
    run(python, "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0]))
    run(python, "-I", "-m", "pip", "check")
    run(python, "-I", "-c", "import bulldog, bulldog.dispatcher, bulldog.production_gate; "
        "from importlib.resources import files; "
        "assert files('bulldog').joinpath('_namespace_launcher.sh').is_file()")
    run(str(environment / "bin/bull"), "--help")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(artifacts.iterdir())}
    (artifacts / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in hashes.items()))
    (out / "report.json").write_text(json.dumps({"commit": commit, "status": "PASS",
        "wheel_built_from_sdist": True, "fresh_install": True, "artifacts": hashes}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
