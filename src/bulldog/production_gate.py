from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import os
from urllib.parse import urlsplit

from .approval_crypto import ApprovalError
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


@dataclass(frozen=True)
class ProductionGateCheck:
    control_id: str
    status: str
    detail: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "detail": self.detail,
            "evidence": dict(self.evidence),
        }


def _pass(control_id: str, **evidence) -> ProductionGateCheck:
    return ProductionGateCheck(control_id, "PASS", evidence=evidence)


def _blocked(control_id: str, detail: str, **evidence) -> ProductionGateCheck:
    return ProductionGateCheck(control_id, "BLOCKED", detail, evidence)


def _fail(control_id: str, detail: str, **evidence) -> ProductionGateCheck:
    return ProductionGateCheck(control_id, "FAIL", detail, evidence)


def _check_remote_anchor() -> ProductionGateCheck:
    control_id = "AUDIT.REMOTE_ANCHOR_CONFIG"
    if os.environ.get("BULL_AUDIT_TRANSPORT") == "relay":
        try:
            transport = production_transport_from_environment()
        except (OSError, ValueError) as exc:
            return _fail(
                control_id,
                "production audit transport is invalid: " + str(exc),
            )
        return _pass(
            control_id,
            transport=type(transport).__name__,
            mode="relay",
        )

    raw = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL", "").strip()
    if not raw:
        return _blocked(control_id, "remote audit anchor is not configured")
    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        return _fail(
            control_id,
            "remote audit anchor URL is invalid: " + str(exc),
        )
    if parsed.scheme != "https" or not parsed.hostname:
        return _fail(
            control_id,
            "remote audit anchor must be an absolute HTTPS URL",
        )
    if parsed.username or parsed.password:
        return _fail(
            control_id,
            "remote audit anchor URL credentials are forbidden",
        )
    if not os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY"):
        return _blocked(
            control_id,
            "remote audit anchor authentication key is not configured",
        )
    try:
        transport = production_transport_from_environment()
    except (OSError, ValueError) as exc:
        return _fail(
            control_id,
            "production audit transport is invalid: " + str(exc),
        )
    return _pass(
        control_id,
        transport=type(transport).__name__,
        scheme=parsed.scheme,
        host=parsed.hostname,
    )


def _check_policy_bundle() -> ProductionGateCheck:
    control_id = "INTEGRITY.SIGNED_POLICY"
    path = os.environ.get("BULL_POLICY_BUNDLE", "").strip()
    key = os.environ.get("BULL_POLICY_BUNDLE_KEY", "")
    if not path:
        return _blocked(
            control_id,
            "signed production policy bundle is not configured",
        )
    if not key:
        return _blocked(
            control_id,
            "production policy verification key is not configured",
        )
    try:
        policy = load_policy_bundle(path, key)
    except (OSError, ValueError, PolicyBundleError, ApprovalError) as exc:
        return _fail(
            control_id,
            "policy bundle verification failed: " + str(exc),
        )
    return _pass(
        control_id,
        path=str(Path(path).resolve()),
        key_id=policy.key_id,
        capability_count=len(policy.capability_ceiling),
        human_approval="human_approval" in policy.raw,
    )


def _check_snapshot_scratch() -> ProductionGateCheck:
    control_id = "STORAGE.SNAPSHOT_SCRATCH"
    raw = os.environ.get("BULL_SNAPSHOT_ROOT", "").strip()
    if not raw:
        return _blocked(
            control_id,
            "production snapshot scratch root is not configured",
        )
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
        return _fail(
            control_id,
            "snapshot scratch validation failed: " + str(exc),
        )
    return _pass(
        control_id,
        path=str(path),
        free_bytes=free,
        reserve_bytes=budget.snapshot_min_free_bytes,
    )


def _check_audit_ledger_path() -> ProductionGateCheck:
    control_id = "AUDIT.LEDGER_CONFIG"
    raw = os.environ.get("BULL_AUDIT_LEDGER", "").strip()
    if not raw:
        return _blocked(
            control_id,
            "production audit ledger path is not configured",
        )
    path = Path(raw)
    if not path.is_absolute():
        return _fail(
            control_id,
            "production audit ledger path must be absolute",
        )
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        return _fail(
            control_id,
            "production audit ledger parent is unavailable: " + str(exc),
        )
    if not os.access(parent, os.W_OK | os.X_OK):
        return _fail(
            control_id,
            "production audit ledger parent is not writable",
        )
    return _pass(
        control_id,
        path=str(path),
        parent=str(parent),
    )


def _check_cgroup_parent() -> ProductionGateCheck:
    control_id = "SANDBOX.CGROUP_DELEGATION"
    raw = os.environ.get("BULL_CGROUP_PARENT", "").strip()
    if not raw:
        return _blocked(
            control_id,
            "delegated cgroup v2 parent is not configured",
        )
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        return _fail(
            control_id,
            "delegated cgroup parent is unavailable: " + str(exc),
        )
    if not path.is_dir():
        return _fail(
            control_id,
            "delegated cgroup parent is not a directory",
        )
    if not os.access(path, os.W_OK | os.X_OK):
        return _fail(
            control_id,
            "delegated cgroup parent is not writable",
        )
    if not (path / "cgroup.procs").exists():
        return _fail(
            control_id,
            "delegated cgroup parent does not expose cgroup.procs",
        )
    return _pass(control_id, path=str(path))


def _check_seccomp_profile() -> ProductionGateCheck:
    control_id = "SANDBOX.SECCOMP_PROFILE"
    profile = os.environ.get("BULL_SECCOMP_PROFILE", "").strip().lower()
    if not profile:
        return _blocked(
            control_id,
            "production requires BULL_SECCOMP_PROFILE=strict",
        )
    if profile != "strict":
        return _fail(
            control_id,
            "production requires BULL_SECCOMP_PROFILE=strict",
            configured=profile,
        )
    return _pass(control_id, configured=profile)


def _check_integrity_manifest(
    *,
    package_root: str | Path | None,
    require_signature: bool,
) -> ProductionGateCheck:
    control_id = "INTEGRITY.SIGNED_RUNTIME"
    manifest_path_raw = os.environ.get("BULL_INTEGRITY_MANIFEST")
    if not manifest_path_raw:
        return _blocked(control_id, "integrity manifest is not configured")
    if package_root is None:
        return _blocked(
            control_id,
            "package root is required for integrity verification",
        )
    signature_key = os.environ.get("BULL_INTEGRITY_MANIFEST_KEY")
    if require_signature and not signature_key:
        return _blocked(
            control_id,
            "integrity manifest signing key is not configured",
        )
    try:
        manifest_path = Path(manifest_path_raw).resolve(strict=True)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_integrity_manifest(
            package_root,
            manifest,
            signature_key=signature_key,
            require_signature=require_signature,
        )
    except (OSError, ValueError, KeyError, IntegrityViolation) as exc:
        return _fail(
            control_id,
            "integrity verification failed: " + str(exc),
        )
    return _pass(
        control_id,
        path=str(manifest_path),
        signed=require_signature,
    )


def evaluate_production_environment(
    requirements: ProductionRequirements = ProductionRequirements(),
    *,
    package_root: str | Path | None = None,
) -> dict:
    checks: list[ProductionGateCheck] = []
    host: dict | None = None

    if requirements.require_remote_audit_anchor:
        checks.append(_check_remote_anchor())
    if requirements.require_signed_policy_bundle:
        checks.append(_check_policy_bundle())
    if requirements.require_snapshot_scratch:
        checks.append(_check_snapshot_scratch())
    if requirements.require_audit_ledger_path:
        checks.append(_check_audit_ledger_path())
    if requirements.require_delegated_cgroup:
        checks.append(_check_cgroup_parent())
    if requirements.require_strict_seccomp:
        checks.append(_check_seccomp_profile())

    if requirements.require_backend_certification:
        host = certify_host(
            dynamic=requirements.require_dynamic_backend_attestation,
            seccomp_profile="strict" if requirements.require_strict_seccomp else "compat",
        )
        if not host.get("certified", False):
            detail = host.get("dynamic_error") or "host backend certification failed"
            checks.append(
                _fail(
                    "SANDBOX.BACKEND_CERTIFICATION",
                    "host backend certification failed: " + str(detail),
                    host=host,
                )
            )
        else:
            checks.append(
                _pass(
                    "SANDBOX.BACKEND_CERTIFICATION",
                    dynamic=requirements.require_dynamic_backend_attestation,
                    host=host,
                )
            )

    if requirements.require_integrity_manifest:
        checks.append(
            _check_integrity_manifest(
                package_root=package_root,
                require_signature=requirements.require_signed_integrity_manifest,
            )
        )

    failures = [
        item.detail or (item.control_id + " did not pass")
        for item in checks
        if item.status != "PASS"
    ]
    return {
        "format": "bull-production-gate-evidence-v1",
        "passed": not failures,
        "checks": [item.to_dict() for item in checks],
        "failures": failures,
        "host": host,
    }


def verify_production_environment(
    requirements: ProductionRequirements = ProductionRequirements(),
    *,
    package_root: str | Path | None = None,
) -> None:
    report = evaluate_production_environment(
        requirements=requirements,
        package_root=package_root,
    )
    if not report["passed"]:
        raise ProductionGateFailure("; ".join(report["failures"]))
