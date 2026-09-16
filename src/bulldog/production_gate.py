from __future__ import annotations

from dataclasses import dataclass
import os


class ProductionGateFailure(
    RuntimeError
):
    pass


@dataclass(frozen=True)
class ProductionRequirements:

    require_remote_audit_anchor: bool = True

    require_backend_certification: bool = True

    require_integrity_manifest: bool = True


def verify_production_environment(
    requirements:
        ProductionRequirements
        = ProductionRequirements(),
) -> None:

    failures = []

    if (
        requirements.require_remote_audit_anchor
        and not os.environ.get(
            "BULL_REMOTE_AUDIT_ANCHOR_URL"
        )
    ):
        failures.append(
            "remote audit anchor is not configured"
        )

    if (
        requirements.require_backend_certification
        and os.environ.get(
            "BULL_HOST_CERTIFIED"
        ) != "1"
    ):
        failures.append(
            "host backend is not certified"
        )

    if (
        requirements.require_integrity_manifest
        and not os.environ.get(
            "BULL_INTEGRITY_MANIFEST"
        )
    ):
        failures.append(
            "integrity manifest is not configured"
        )

    if failures:

        raise ProductionGateFailure(
            "; ".join(
                failures
            )
        )
