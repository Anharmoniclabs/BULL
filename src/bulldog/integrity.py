from __future__ import annotations

from pathlib import Path
import hashlib
import json
import platform


class IntegrityViolation(
    RuntimeError
):
    pass


CRITICAL_FILES = (
    "audit.py",
    "canonicalizer.py",
    "dispatcher.py",
    "egress_proxy.py",
    "engine.py",
    "malware_scanner.py",
    "namespace_sandbox.py",
    "policy.py",
    "runtime.py",
    "seccomp_policy.py",
    "secret_broker.py",
    "session_guard.py",
    "snapshot.py",
    "trace_model.py",
    "trace_runtime.py",
)


def sha256_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as fh:

        while True:

            block = fh.read(
                1024 * 1024
            )

            if not block:
                break

            digest.update(
                block
            )

    return digest.hexdigest()


def build_integrity_manifest(
    package_root:
        str
        | Path,
) -> dict:

    package_root = Path(
        package_root
    )

    files = {}

    for name in CRITICAL_FILES:

        path = (
            package_root
            / name
        )

        if not path.exists():
            raise IntegrityViolation(
                f"critical file missing: {name}"
            )

        files[
            name
        ] = sha256_file(
            path
        )

    return {
        "format":
            "bull-integrity-v1",

        "platform":
            platform.platform(),

        "files":
            files,
    }


def verify_integrity_manifest(
    package_root:
        str
        | Path,
    manifest: dict,
) -> None:

    actual = (
        build_integrity_manifest(
            package_root
        )
    )

    expected_files = (
        manifest.get(
            "files",
            {}
        )
    )

    if (
        actual["files"]
        != expected_files
    ):
        raise IntegrityViolation(
            "trusted computing base hash mismatch"
        )
