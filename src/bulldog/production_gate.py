from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import os
from urllib.parse import urlsplit

from .host_certify import certify_host
from .integrity import IntegrityViolation, verify_integrity_manifest
from .policy_bundle import PolicyBundleError, load_policy_bundle
from .workspace_limits import WorkspaceBudget, WorkspaceLimitViolation
from .audit_transport import production_transport_from_environment


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
    require_signed_policy_bundle: bool = True
    require_snapshot_scratch: bool = True
    require_audit_ledger_path: bool = True
    require_delegated_cgroup: bool = True


def _validate_remote_anchor(failures: list[str]) -> None:
    if os.environ.get("BULL_AUDIT_TRANSPORT") == "relay":
        try:
            production_transport_from_environment()
        except (OSError, ValueError) as exc:
            failures.append("production audit transport is invalid: " + str(exc))
        return
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
    try:
        production_transport_from_environment()
    except (OSError, ValueError) as exc:
        failures.append("production audit transport is invalid: " + str(exc))


def _validate_policy_bundle(failures: list[str]) -> None:
    path = os.environ.get("BULL_POLICY_BUNDLE", "").strip()
    key = os.environ.get("BULL_POLICY_BUNDLE_KEY", "")
    if not path:
        failures.append("signed production policy bundle is not configured")
        return
    if not key:
        failures.append("production policy verification key is not configured")
        return
    try:
        load_policy_bundle(path, key)
    except (OSError, ValueError, PolicyBundleError) as exc:
        failures.append("policy bundle verification failed: " + str(exc))


def _validate_snapshot_scratch(failures: list[str]) -> None:
    raw = os.environ.get("BULL_SNAPSHOT_ROOT", "").strip()
    if not raw:
        failures.append("production snapshot scratch root is not configured")
        return
    try:
        path = Path(raw).resolve(strict=True)
        if not path.is_dir():
            raise WorkspaceLimitViolation("snapshot scratch root is not a directory")
        if not os.access(path, os.W_OK | os.X_OK):
            raise WorkspaceLimitViolation("snapshot scratch root is not writable")
        budget = WorkspaceBudget.from_environment()
        statvfs = os.statvfs(path)
        free = statvfs.f_bavail * statvfs.f_frsize
        if free < budget.snapshot_min_free_bytes:
            raise WorkspaceLimitViolation(
                "snapshot scratch root lacks the configured free-space reserve"
            )
    except (OSError, ValueError, WorkspaceLimitViolation) as exc:
        failures.append("snapshot scratch validation failed: " + str(exc))


def _validate_audit_ledger_path(failures: list[str]) -> None:
    raw = os.environ.get("BULL_AUDIT_LEDGER", "").strip()
    if not raw:
        failures.append("production audit ledger path is not configured")
        return
    path = Path(raw)
    if not path.is_absolute():
        failures.append("production audit ledger path must be absolute")
        return
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        failures.append("production audit ledger parent is unavailable: " + str(exc))
        return
    if not os.access(parent, os.W_OK | os.X_OK):
        failures.append("production audit ledger parent is not writable")


def _validate_cgroup_parent(failures: list[str]) -> None:
    raw = os.environ.get("BULL_CGROUP_PARENT", "").strip()
    if not raw:
        failures.append("delegated cgroup v2 parent is not configured")
        return
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        failures.append("delegated cgroup parent is unavailable: " + str(exc))
        return
    if not path.is_dir():
        failures.append("delegated cgroup parent is not a directory")
        return
    if not os.access(path, os.W_OK | os.X_OK):
        failures.append("delegated cgroup parent is not writable")
    if not (path / "cgroup.procs").exists():
        failures.append("delegated cgroup parent does not expose cgroup.procs")


def verify_production_environment(
    requirements: ProductionRequirements = ProductionRequirements(),
    *,
    package_root: str | Path | None = None,
) -> None:
    failures: list[str] = []

    if requirements.require_remote_audit_anchor:
        _validate_remote_anchor(failures)
    if requirements.require_signed_policy_bundle:
        _validate_policy_bundle(failures)
    if requirements.require_snapshot_scratch:
        _validate_snapshot_scratch(failures)
    if requirements.require_audit_ledger_path:
        _validate_audit_ledger_path(failures)
    if requirements.require_delegated_cgroup:
        _validate_cgroup_parent(failures)

    if requirements.require_strict_seccomp:
        profile = os.environ.get("BULL_SECCOMP_PROFILE", "").strip().lower()
        if profile != "strict":
            failures.append("production requires BULL_SECCOMP_PROFILE=strict")

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
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    verify_integrity_manifest(
                        package_root,
                        manifest,
                        signature_key=signature_key,
                        require_signature=requirements.require_signed_integrity_manifest,
                    )
                except (OSError, ValueError, KeyError, IntegrityViolation) as exc:
                    failures.append("integrity verification failed: " + str(exc))

    if failures:
        raise ProductionGateFailure("; ".join(failures))
