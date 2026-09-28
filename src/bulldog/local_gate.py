"""Local execution requires the same host protections and a local audit checkpoint."""

from .local_audit import local_ledger_from_environment
from .production_gate import ProductionRequirements, evaluate_production_environment


class LocalGateFailure(RuntimeError):
    pass


def evaluate_local_environment(*, package_root=None):
    report = evaluate_production_environment(
        ProductionRequirements(require_remote_audit_anchor=False),
        package_root=package_root,
    )
    report.update(format="bull-local-gate-evidence-v1", audit_mode="local")
    check = {"control_id": "AUDIT.LOCAL_CHECKPOINT", "status": "PASS", "detail": ""}
    try:
        local_ledger_from_environment()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        check.update(status="BLOCKED", detail="local audit unavailable: " + str(exc))
        report["failures"].append(check["detail"])
    report["checks"].append(check)
    report["passed"] = not report["failures"]
    return report


def verify_local_environment(*, package_root=None):
    report = evaluate_local_environment(package_root=package_root)
    if not report["passed"]:
        raise LocalGateFailure("; ".join(report["failures"]))
