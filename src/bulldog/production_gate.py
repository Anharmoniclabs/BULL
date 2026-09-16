from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os

from .host_certify import certify_host
from .integrity import (
    IntegrityViolation,
    verify_integrity_manifest,
)


class ProductionGateFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class ProductionRequirements:
    require_remote_audit_anchor: bool = True
    require_backend_certification: bool = True
    require_integrity_manifest: bool = True


def verify_production_environment(
    requirements: ProductionRequirements = ProductionRequirements(),
    *,
    package_root: str | Path | None = None,
) -> None:
    failures = []

    if (
        requirements.require_remote_audit_anchor
        and not os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL")
    ):
        failures.append("remote audit anchor is not configured")

    if requirements.require_backend_certification:
        host = certify_host()
        if not host.get("certified", False):
            failures.append("host backend certification failed")

    if requirements.require_integrity_manifest:
        manifest_path_raw = os.environ.get("BULL_INTEGRITY_MANIFEST")
        if not manifest_path_raw:
            failures.append("integrity manifest is not configured")
        elif package_root is None:
            failures.append("package root is required for integrity verification")
        else:
            manifest_path = Path(manifest_path_raw).resolve(strict=True)
            try:
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                verify_integrity_manifest(package_root, manifest)
            except (
                OSError,
                ValueError,
                KeyError,
                IntegrityViolation,
            ) as exc:
                failures.append(
                    "integrity verification failed: " + str(exc)
                )

    if failures:
        raise ProductionGateFailure("; ".join(failures))
