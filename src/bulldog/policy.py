from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .canonicalizer import is_sensitive_filesystem_resource
from .models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
    has_external_provenance,
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
    Capability.FS_WRITE_HOST,
    Capability.PACKAGE_INSTALL,
    Capability.AGENT_SPAWN,
}

BROKERED_SECRET_OPERATIONS = {
    "secret.get",
    "credential.get",
    "credential.read",
}

PERSISTENCE_PATHS = (
    "/.bashrc",
    "/.zshrc",
    "/.profile",
    "/.bash_profile",
    "/.ssh/authorized_keys",
    "/.config/autostart/",
    "/.config/systemd/",
    "/etc/systemd/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/environment",
    "/etc/ld.so.preload",
    "/etc/modules-load.d/",
    "/etc/sysctl.d/",
    "/etc/cron",
    "/crontab",
)

SECRET_HINTS = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "access_key",
    "session_key",
    "bearer",
)


@dataclass
class DeterministicPolicy:
    project_root: str = "/workspace"
    global_capability_ceiling: frozenset[Capability] | None = None

    def evaluate(self, action: ActionRequest) -> Evaluation:
        reasons: list[str] = []
        risk = 0.0

        if (
            self.global_capability_ceiling is not None
            and action.capability not in self.global_capability_ceiling
        ):
            return Evaluation(
                Decision.DENY,
                1.0,
                ("capability is outside the signed deployment policy ceiling",),
                hard_block=True,
            )

        if action.capability not in action.granted_capabilities:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("requested capability was not explicitly granted",),
                hard_block=True,
            )

        if (
            action.parent_capabilities is not None
            and action.capability not in action.parent_capabilities
        ):
            return Evaluation(
                Decision.DENY,
                1.0,
                (
                    "child agent attempted to exercise authority "
                    "not held by its parent",
                ),
                hard_block=True,
            )

        raw_resource = action.resource
        decoded_resource = unquote(raw_resource)
        decoded_lower = decoded_resource.lower()

        raw_parts = raw_resource.replace("\\", "/").split("/")
        decoded_parts = decoded_resource.replace("\\", "/").split("/")

        if ".." in raw_parts:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("parent-directory traversal detected",),
                hard_block=True,
            )

        if ".." in decoded_parts:
            return Evaluation(
                Decision.DENY,
                1.0,
                ("encoded parent-directory traversal detected",),
                hard_block=True,
            )

        normalized = str(PurePosixPath(decoded_resource))

        if action.capability in {
            Capability.FS_READ_PROJECT,
            Capability.FS_WRITE_PROJECT,
        }:
            project_path = PurePosixPath(self.project_root)
            resource_path = PurePosixPath(normalized)

            try:
                resource_path.relative_to(project_path)
            except ValueError:
                return Evaluation(
                    Decision.DENY,
                    1.0,
                    (
                        "project-scoped capability attempted to access "
                        "resource outside project root",
                    ),
                    hard_block=True,
                )

        if any(marker.lower() in decoded_lower for marker in CANARY_MARKERS):
            return Evaluation(
                Decision.DENY,
                1.0,
                ("canary/honeypot resource accessed",),
                hard_block=True,
            )

        if is_sensitive_filesystem_resource(normalized):
            reasons.append("resource is security-sensitive")
            risk += 0.70

        persistence_target = any(
            marker in decoded_lower
            for marker in PERSISTENCE_PATHS
        )

        if (
            persistence_target
            and action.capability
            in {
                Capability.FS_WRITE_HOME,
                Capability.FS_WRITE_HOST,
                Capability.SECURITY_CONTROL_WRITE,
            }
        ):
            reasons.append(
                "write targets a resource capable of persisting beyond session"
            )
            risk = max(risk, 0.90)

        external = has_external_provenance(action.provenance)

        if external:
            reasons.append(
                "action is downstream of untrusted external content"
            )
            risk += 0.25

        # An externally influenced agent should not silently gain visibility
        # into the host or user home merely because a broad capability was
        # accidentally granted. Require explicit review.
        if external and action.capability in {
            Capability.FS_READ_HOME,
            Capability.FS_READ_HOST,
        }:
            reasons.append(
                "externally influenced non-project filesystem read requires review"
            )
            risk = max(risk, 0.90)

        if external and action.capability in {
            Capability.FS_WRITE_HOME,
            Capability.FS_WRITE_HOST,
            Capability.SECURITY_CONTROL_WRITE,
        }:
            reasons.append(
                "externally influenced non-project filesystem write requires review"
            )
            risk = max(risk, 0.95)

        if (
            action.capability == Capability.CREDENTIAL_READ
            and action.operation.lower().strip() in BROKERED_SECRET_OPERATIONS
        ):
            if external:
                return Evaluation(
                    Decision.DENY,
                    1.0,
                    tuple(
                        reasons
                        + [
                            "externally influenced credential access is forbidden"
                        ]
                    ),
                    hard_block=True,
                )
            return Evaluation(
                Decision.ALLOW,
                max(risk, 0.20),
                (
                    "credential access is mediated by the scoped secret broker",
                ),
                hard_block=False,
            )

        if action.capability in HIGH_RISK_CAPABILITIES:
            reasons.append("high-risk capability")
            risk += 0.55

        if external and action.capability == Capability.PROCESS_EXEC:
            reasons.append(
                "externally influenced process execution requires review"
            )
            risk = max(risk, 0.90)

        if external and action.capability == Capability.AGENT_SPAWN:
            reasons.append(
                "externally influenced agent creation requires review"
            )
            risk = max(risk, 0.90)

        if external and action.capability == Capability.CREDENTIAL_READ:
            return Evaluation(
                Decision.DENY,
                1.0,
                tuple(
                    reasons
                    + [
                        "externally influenced credential access is forbidden"
                    ]
                ),
                hard_block=True,
            )

        if external and action.capability == Capability.NETWORK_POST:
            reasons.append(
                "externally influenced outbound data transfer"
            )
            risk = max(risk, 0.90)

        if action.capability in {
            Capability.NETWORK_OUTBOUND,
            Capability.NETWORK_POST,
        }:
            try:
                parsed = urlsplit(decoded_resource)
                query = parsed.query.lower()
            except Exception:
                query = decoded_lower

            if any(marker in query for marker in SECRET_HINTS):
                reasons.append(
                    "outbound resource contains possible secret-bearing data"
                )
                risk = max(risk, 0.90)

        if action.external_side_effect:
            reasons.append("operation has an external side effect")
            risk += 0.25

        if action.irreversible:
            reasons.append("operation is marked irreversible")
            risk += 0.35

        risk = min(risk, 1.0)

        if risk >= 0.85:
            decision = Decision.ESCALATE
        elif risk >= 0.55:
            decision = Decision.SANDBOX
        else:
            decision = Decision.ALLOW

        if not reasons:
            reasons.append("within explicitly granted capability envelope")

        return Evaluation(
            decision,
            risk,
            tuple(reasons),
            hard_block=False,
        )
