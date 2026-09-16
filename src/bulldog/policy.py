from __future__ import annotations

import posixpath
from dataclasses import dataclass

from .models import ActionRequest, Capability, Decision, Evaluation, has_external_provenance
from .security_flags import (
    CANARY_TOUCHED,
    CAPABILITY_NOT_GRANTED,
    CHILD_AUTHORITY_ESCALATION,
    EXTERNAL_DATA_TRANSFER,
    IRREVERSIBLE_ACTION,
    POSSIBLE_SECRET_EXFILTRATION,
    POSSIBLE_SIDE_CHANNEL,
    RESOURCE_CAPABILITY_MISMATCH,
    RESOURCE_NOT_RESOLVED,
    SECURITY_CONTROL_TAMPERING,
    SENSITIVE_RESOURCE,
    UNTRUSTED_CREDENTIAL_ACCESS,
    UNTRUSTED_TO_AGENT_SPAWN,
    UNTRUSTED_TO_EXECUTION,
    UNTRUSTED_TO_HOME_WRITE,
    UNTRUSTED_TO_INSTALL,
    UNVERIFIED_CONTEXT,
)


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
    Capability.PROCESS_EXEC,
    Capability.AGENT_SPAWN,
    Capability.FS_WRITE_HOME,
}

PROJECT_CAPABILITIES = {
    Capability.FS_READ_PROJECT,
    Capability.FS_WRITE_PROJECT,
}

EXFILTRATION_CAPABILITIES = {
    Capability.NETWORK_OUTBOUND,
    Capability.NETWORK_POST,
    Capability.AGENT_MESSAGE,
}


def _normalize(path: str) -> str:
    return posixpath.normpath(path)


def _inside(root: str, path: str) -> bool:
    root_n = _normalize(root)
    path_n = _normalize(path)
    if not root_n.startswith("/") or not path_n.startswith("/"):
        return False
    return path_n == root_n or path_n.startswith(root_n.rstrip("/") + "/")


@dataclass
class DeterministicPolicy:
    project_root: str = "/workspace"
    require_verified_context: bool = True

    def evaluate(self, action: ActionRequest) -> Evaluation:
        reasons: list[str] = []
        flags = []
        risk = 0.0

        # The model must never be allowed to self-assert identity, provenance,
        # capabilities, parent authority, canonical paths, or secret taint.
        if self.require_verified_context and not action.security_context_verified:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("security context was not verified by the trusted host boundary",),
                hard_block=True,
                flags=(UNVERIFIED_CONTEXT,),
            )

        if action.capability not in action.granted_capabilities:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("requested capability was not explicitly granted by the trusted host",),
                hard_block=True,
                flags=(CAPABILITY_NOT_GRANTED,),
            )

        if action.parent_capabilities is not None and action.capability not in action.parent_capabilities:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("child agent attempted to exercise authority not held by its parent",),
                hard_block=True,
                flags=(CHILD_AUTHORITY_ESCALATION,),
            )

        # Filesystem security decisions use the host-resolved path, not the
        # model-supplied string. Without it, symlink/redirect safety is unknown.
        fs_capability = action.capability in {
            Capability.FS_READ_PROJECT,
            Capability.FS_WRITE_PROJECT,
            Capability.FS_READ_HOME,
            Capability.FS_WRITE_HOME,
            Capability.CREDENTIAL_READ,
        }
        if fs_capability and action.resolved_resource is None:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("filesystem resource was not resolved by the trusted host before policy evaluation",),
                hard_block=True,
                flags=(RESOURCE_NOT_RESOLVED,),
            )

        inspected_resource = _normalize(action.resolved_resource or action.resource)

        if action.capability in PROJECT_CAPABILITIES and not _inside(self.project_root, inspected_resource):
            return Evaluation(
                Decision.DENY,
                1.0,
                ("project-scoped filesystem capability was used for a resource outside the project root",),
                hard_block=True,
                flags=(RESOURCE_CAPABILITY_MISMATCH,),
            )

        if any(marker.lower() in inspected_resource.lower() for marker in CANARY_MARKERS):
            return Evaluation(
                Decision.DENY,
                1.0,
                ("canary/honeypot resource accessed",),
                hard_block=True,
                flags=(CANARY_TOUCHED,),
            )

        sensitive = any(marker.lower() in inspected_resource.lower() for marker in SENSITIVE_PATH_MARKERS)
        if sensitive:
            flags.append(SENSITIVE_RESOURCE)
            reasons.append("resolved resource is security-sensitive")
            risk += 0.7
            if action.capability != Capability.CREDENTIAL_READ:
                return Evaluation(
                    Decision.DENY,
                    1.0,
                    tuple(reasons + ["security-sensitive resource was reached through a non-credential capability"]),
                    hard_block=True,
                    flags=tuple(flags + [RESOURCE_CAPABILITY_MISMATCH]),
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
            flags.append(IRREVERSIBLE_ACTION)
            risk += 0.35

        # Secret-derived data may not cross an observable boundary. This catches
        # direct sends plus transformed/encoded data when taint is preserved by
        # the trusted runtime.
        if action.secret_taint and action.capability in EXFILTRATION_CAPABILITIES:
            return Evaluation(
                Decision.DENY,
                1.0,
                tuple(reasons + ["secret-derived data is crossing an external or inter-agent boundary"]),
                hard_block=True,
                flags=tuple(flags + [POSSIBLE_SECRET_EXFILTRATION]),
            )

        if action.secret_taint and action.external_side_effect:
            return Evaluation(
                Decision.ESCALATE,
                0.95,
                tuple(reasons + ["secret-derived state is influencing an externally observable action"]),
                hard_block=False,
                flags=tuple(flags + [POSSIBLE_SIDE_CHANNEL]),
            )

        if external and action.capability == Capability.CREDENTIAL_READ:
            return Evaluation(
                Decision.DENY,
                1.0,
                tuple(reasons + ["externally influenced credential access is forbidden"]),
                hard_block=True,
                flags=tuple(flags + [UNTRUSTED_CREDENTIAL_ACCESS]),
            )

        if external and action.capability == Capability.SECURITY_CONTROL_WRITE:
            return Evaluation(
                Decision.DENY,
                1.0,
                tuple(reasons + ["untrusted content may not modify security controls"]),
                hard_block=True,
                flags=tuple(flags + [SECURITY_CONTROL_TAMPERING]),
            )

        if external and action.capability == Capability.PROCESS_EXEC:
            risk = max(risk, 0.90)
            flags.append(UNTRUSTED_TO_EXECUTION)
            reasons.append("untrusted content is influencing process execution")

        if external and action.capability == Capability.PACKAGE_INSTALL:
            risk = max(risk, 0.90)
            flags.append(UNTRUSTED_TO_INSTALL)
            reasons.append("untrusted content is influencing software installation")

        if external and action.capability == Capability.AGENT_SPAWN:
            risk = max(risk, 0.90)
            flags.append(UNTRUSTED_TO_AGENT_SPAWN)
            reasons.append("untrusted content is influencing creation of another agent")

        if external and action.capability == Capability.FS_WRITE_HOME:
            risk = max(risk, 0.90)
            flags.append(UNTRUSTED_TO_HOME_WRITE)
            reasons.append("untrusted content is influencing writes outside the project area")

        if external and action.capability in {Capability.NETWORK_POST, Capability.NETWORK_OUTBOUND}:
            risk = max(risk, 0.75)
            flags.append(EXTERNAL_DATA_TRANSFER)
            reasons.append("untrusted content is influencing outbound network activity")

        risk = min(risk, 1.0)
        if risk >= 0.85:
            decision = Decision.ESCALATE
        elif risk >= 0.55:
            decision = Decision.SANDBOX
        else:
            decision = Decision.ALLOW

        if not reasons:
            reasons.append("within verified capability and resource boundaries")

        return Evaluation(decision, risk, tuple(reasons), hard_block=False, flags=tuple(flags))
