from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
from urllib.parse import urlsplit

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
    require_dynamic_backend_attestation: bool = True
    require_integrity_manifest: bool = True
    require_signed_integrity_manifest: bool = True
    require_strict_seccomp: bool = True


def _validate_remote_anchor(failures: list[str]) -> None:
    raw = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL", "").strip()
    if not raw:
        failures.append("remote audit anchor is not configured")
        return

    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        failures.append("remote audit anchor URL is invalid: " + str(exc))
        return

    if parsed.scheme != "https" or not parsed.hostname:
        failures.append("remote audit anchor must be an absolute HTTPS URL")
    if parsed.username or parsed.password:
        failures.append("remote audit anchor URL credentials are forbidden")
    if not os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY"):
        failures.append("remote audit anchor authentication key is not configured")


def verify_production_environment(
    requirements: ProductionRequirements = ProductionRequirements(),
    *,
    package_root: str | Path | None = None,
) -> None:
    failures: list[str] = []

    if requirements.require_remote_audit_anchor:
        _validate_remote_anchor(failures)

    if requirements.require_strict_seccomp:
        profile = os.environ.get("BULL_SECCOMP_PROFILE", "").strip().lower()
        if profile != "strict":
            failures.append(
                "production requires BULL_SECCOMP_PROFILE=strict"
            )

    if requirements.require_backend_certification:
        host = certify_host(
            dynamic=requirements.require_dynamic_backend_attestation,
            seccomp_profile="strict" if requirements.require_strict_seccomp else "compat",
        )
        if not host.get("certified", False):
            detail = host.get("dynamic_error") or "host backend certification failed"
            failures.append("host backend certification failed: " + str(detail))

    if requirements.require_integrity_manifest:
        manifest_path_raw = os.environ.get("BULL_INTEGRITY_MANIFEST")
        if not manifest_path_raw:
            failures.append("integrity manifest is not configured")
        elif package_root is None:
            failures.append("package root is required for integrity verification")
        else:
            signature_key = os.environ.get("BULL_INTEGRITY_MANIFEST_KEY")
            if requirements.require_signed_integrity_manifest and not signature_key:
                failures.append("integrity manifest signing key is not configured")
            else:
                try:
                    manifest_path = Path(manifest_path_raw).resolve(strict=True)
                    manifest = json.loads(
                        manifest_path.read_text(encoding="utf-8")
                    )
                    verify_integrity_manifest(
                        package_root,
                        manifest,
                        signature_key=signature_key,
                        require_signature=requirements.require_signed_integrity_manifest,
                    )
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
