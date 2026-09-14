from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .models import ActionRequest, Capability, Decision, Evaluation, has_external_provenance


SENSITIVE_PATH_MARKERS = (
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.config/gcloud/",
    "/etc/shadow",
    "/etc/sudoers",
)

CANARY_MARKERS = (
    "AI_CANARY_KEY",
    ".bulldog-canary",
    "sentinel_admin_token",
    "agent_mailbox_canary",
)

HIGH_RISK_CAPABILITIES = {
    Capability.CREDENTIAL_READ,
    Capability.SECURITY_CONTROL_WRITE,
    Capability.PACKAGE_INSTALL,
}


@dataclass
class DeterministicPolicy:
    project_root: str = "/workspace"

    def evaluate(self, action: ActionRequest) -> Evaluation:
        reasons: list[str] = []
        risk = 0.0

        if action.capability not in action.granted_capabilities:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("requested capability was not explicitly granted",),
                hard_block=True,
            )

        if action.parent_capabilities is not None and action.capability not in action.parent_capabilities:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("child agent attempted to exercise authority not held by its parent",),
                hard_block=True,
            )

        normalized = str(PurePosixPath(action.resource))
        if any(marker in normalized for marker in SENSITIVE_PATH_MARKERS):
            if action.capability != Capability.CREDENTIAL_READ:
                reasons.append("resource is security-sensitive")
                risk += 0.7

        if any(marker.lower() in normalized.lower() for marker in CANARY_MARKERS):
            return Evaluation(
                Decision.DENY,
                1.0,
                ("canary/honeypot resource accessed",),
                hard_block=True,
            )

        external = has_external_provenance(action.provenance)
        if external:
            reasons.append("action is downstream of untrusted external content")
            risk += 0.25

        if action.capability in HIGH_RISK_CAPABILITIES:
            reasons.append("high-risk capability")
            risk += 0.55

        if action.external_side_effect:
            reasons.append("operation has an external side effect")
            risk += 0.25

        if action.irreversible:
            reasons.append("operation is marked irreversible")
            risk += 0.35

        if external and action.capability == Capability.CREDENTIAL_READ:
            return Evaluation(
                Decision.DENY,
                1.0,
                tuple(reasons + ["externally influenced credential access is forbidden"]),
                hard_block=True,
            )

        if external and action.capability == Capability.NETWORK_POST:
            risk = max(risk, 0.75)
            reasons.append("externally influenced outbound data transfer")

        risk = min(risk, 1.0)
        if risk >= 0.85:
            decision = Decision.ESCALATE
        elif risk >= 0.55:
            decision = Decision.SANDBOX
        else:
            decision = Decision.ALLOW

        if not reasons:
            reasons.append("within explicitly granted capability envelope")

        return Evaluation(decision, risk, tuple(reasons), hard_block=False)
