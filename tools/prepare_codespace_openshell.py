#!/usr/bin/env python3
"""Build the pinned native OpenShell test prerequisites on Linux x86-64.

Explicitly requested by --prepare-openshell. Installs Ubuntu build dependencies
and a pinned Rust toolchain, but neither installs Docker nor starts a gateway.
The gateway enables only the Docker compute driver used by qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess

from openshell_qualification_results import BINARIES, PIN, git, write_json

RUST = "1.95.0"
PACKAGES = ["build-essential", "cmake", "clang", "libclang-dev", "pkg-config",
            "libssl-dev", "musl-tools", "ca-certificates", "curl", "git", "binutils"]


class PrerequisiteBlocked(RuntimeError):
    pass


def validate_source(source):
    if source.is_symlink():
        raise PrerequisiteBlocked("OpenShell build source must not be a symlink")
    if source.exists():
        try:
            if git(source, "rev-parse", "HEAD") != PIN:
                raise PrerequisiteBlocked("Existing OpenShell checkout is not pinned; it was left untouched")
            if git(source, "status", "--porcelain", "--untracked-files=no"):
                raise PrerequisiteBlocked("Existing OpenShell checkout has tracked changes; it was left untouched")
        except subprocess.CalledProcessError as exc:
            raise PrerequisiteBlocked("Existing build directory is not the pinned Git checkout") from exc


def prerequisites(source):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise PrerequisiteBlocked("The qualification Docker image staging currently requires Linux x86-64")
    validate_source(source)
    if not shutil.which("docker"):
        raise PrerequisiteBlocked("Docker is required; this helper does not install Docker")
    try:
        ready = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PrerequisiteBlocked("Docker daemon is not reachable") from exc
    if ready.returncode:
        raise PrerequisiteBlocked("Docker daemon is not reachable; inspect docker info")
    if not shutil.which("apt-get"):
        raise PrerequisiteBlocked("This setup helper requires an Ubuntu/Debian apt-get host")
    if os.geteuid() == 0:
        return []
    if not shutil.which("sudo") or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode:
        raise PrerequisiteBlocked("Build dependency installation requires passwordless sudo on Codespaces")
    return ["sudo", "-n"]


def execute(command, *, cwd=None, env=None, timeout=5400):
    # Commands contain only public package names and build inputs, never keys.
    print("Running:", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout)


def build(source, output, jobs, check_only=False):
    report = {"format": "bull-native-openshell-build-v1", "status": "BLOCKED",
              "source": str(source), "expected_commit": PIN, "rust_toolchain": RUST,
              "gateway_features": ["compute-driver-docker", "bundled-z3"],
              "scope": "Build prerequisites only; native behavior remains unqualified until the tests run"}
    rc = 2
    try:
        privileged = prerequisites(source)
        if check_only:
            report.update(status="READY_TO_BUILD", reason="Host prerequisites available; binaries were not built or attested")
            rc = 0
            return rc
        source.parent.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            execute(["git", "clone", "--single-branch", "--branch", "v0.1.2",
                     "https://github.com/NVIDIA/OpenShell.git", str(source)], timeout=300)
        validate_source(source)
        # Use bundled Z3 to avoid linking against an incompatible system Z3.
        execute(privileged + ["apt-get", "update"], timeout=600)
        execute(privileged + ["apt-get", "install", "-y", "--no-install-recommends", *PACKAGES], timeout=1200)
        build_env = dict(os.environ)
        build_env["PATH"] = str(Path.home() / ".cargo/bin") + os.pathsep + build_env["PATH"]
        rustup = shutil.which("rustup", path=build_env["PATH"])
        if not rustup:
            installer = output.parent / "rustup-init.sh"
            execute(["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "https://sh.rustup.rs", "-o", str(installer)], timeout=120)
            execute(["sh", str(installer), "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "none"], env=build_env, timeout=600)
            rustup = str(Path.home() / ".cargo/bin/rustup")
        execute([rustup, "toolchain", "install", RUST, "--profile", "minimal"], env=build_env, timeout=900)
        execute([rustup, "target", "add", "--toolchain", RUST, "x86_64-unknown-linux-musl"], env=build_env, timeout=300)
        cargo = shutil.which("cargo", path=build_env["PATH"])
        if not cargo:
            raise RuntimeError("Rustup completed without an available cargo executable")
        build_env.update(CARGO_BUILD_JOBS=str(jobs), CARGO_TARGET_DIR=str(source / "target"),
                         CARGO_INCREMENTAL="0", CARGO_PROFILE_RELEASE_DEBUG="0")
        # An unrelated wrapper can select a foreign compiler/cache unexpectedly.
        build_env.pop("RUSTC_WRAPPER", None)
        execute([cargo, "+" + RUST, "build", "--locked", "--release", "-p", "openshell-cli", "-p", "openshell-supervisor"], cwd=source, env=build_env)
        execute([cargo, "+" + RUST, "build", "--locked", "--release", "-p", "openshell-gateway",
                 "--no-default-features", "--features", "compute-driver-docker,bundled-z3"], cwd=source, env=build_env)
        musl_env = {**build_env, "CC_x86_64_unknown_linux_musl": "musl-gcc",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER": "musl-gcc"}
        execute([cargo, "+" + RUST, "build", "--locked", "--release", "-p", "openshell-sandbox",
                 "--bin", "openshell-sandbox", "--target", "x86_64-unknown-linux-musl"], cwd=source, env=musl_env)
        execute(["bash", str(source / "tasks/scripts/verify-static-binary.sh"), str(source / BINARIES[3])], cwd=source, env=build_env, timeout=30)
        binaries = []
        for name in BINARIES:
            path = source / name
            if not path.is_file() or not os.access(path, os.X_OK):
                raise RuntimeError("Expected executable was not built: " + name)
            execute([str(path), "--help"], env=build_env, timeout=30)
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            binaries.append({"path": name, "bytes": path.stat().st_size, "sha256": digest.hexdigest()})
        validate_source(source)
        report.update(status="BUILT", actual_commit=git(source, "rev-parse", "HEAD"), binaries=binaries)
        rc = 0
    except PrerequisiteBlocked as exc:
        report["reason"] = str(exc)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        report.update(status="FAIL", reason=type(exc).__name__ + ": " + str(exc)[:1000])
        rc = 1
    finally:
        report["exit_code"] = rc
        write_json(output, report)
        print("OpenShell build:", report["status"], report.get("reason", ""), flush=True)
    return rc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--check", action="store_true", help="Read-only prerequisite checks; does not install or build")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    return build(args.source.absolute(), args.report.absolute(), args.jobs, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
