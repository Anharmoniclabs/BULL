from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityFlag:
    code: str
    severity: str
    plain_english: str

    def render(self) -> str:
        return f"[{self.severity}] {self.code}: {self.plain_english}"


def flag(code: str, severity: str, plain_english: str) -> SecurityFlag:
    return SecurityFlag(code=code, severity=severity, plain_english=plain_english)


UNVERIFIED_CONTEXT = flag(
    "UNVERIFIED_SECURITY_CONTEXT",
    "CRITICAL",
    "The action arrived without a host-verified identity, authority, provenance, and resource context. The agent may be describing its own permissions.",
)
CAPABILITY_NOT_GRANTED = flag(
    "CAPABILITY_NOT_GRANTED",
    "CRITICAL",
    "The requested capability is not in the authority envelope assigned by the trusted host.",
)
CHILD_AUTHORITY_ESCALATION = flag(
    "CHILD_AUTHORITY_ESCALATION",
    "CRITICAL",
    "A child agent is trying to use authority that its parent does not hold.",
)
RESOURCE_CAPABILITY_MISMATCH = flag(
    "RESOURCE_CAPABILITY_MISMATCH",
    "CRITICAL",
    "The real resource does not fit the capability being presented for the action. This can indicate capability laundering or a confused-deputy attempt.",
)
RESOURCE_NOT_RESOLVED = flag(
    "RESOURCE_NOT_RESOLVED",
    "HIGH",
    "A filesystem action was evaluated without a host-resolved canonical path. Symlink and path-redirection attacks cannot be ruled out.",
)
CANARY_TOUCHED = flag(
    "CANARY_TOUCHED",
    "CRITICAL",
    "The action touched a canary or honeypot resource. Normal work should not require this access.",
)
SENSITIVE_RESOURCE = flag(
    "SENSITIVE_RESOURCE",
    "HIGH",
    "The resolved resource is security-sensitive, such as credential or host-security material.",
)
UNTRUSTED_TO_EXECUTION = flag(
    "UNTRUSTED_TO_EXECUTION",
    "HIGH",
    "Untrusted external content is directly influencing code or process execution.",
)
UNTRUSTED_TO_INSTALL = flag(
    "UNTRUSTED_TO_INSTALL",
    "HIGH",
    "Untrusted external content is directly influencing a package or software installation.",
)
UNTRUSTED_TO_AGENT_SPAWN = flag(
    "UNTRUSTED_TO_AGENT_SPAWN",
    "HIGH",
    "Untrusted content is trying to create another agent, which can be used to route around the current authority boundary.",
)
UNTRUSTED_TO_HOME_WRITE = flag(
    "UNTRUSTED_TO_HOME_WRITE",
    "HIGH",
    "Untrusted content is trying to write outside the project area into the user's home environment.",
)
UNTRUSTED_CREDENTIAL_ACCESS = flag(
    "UNTRUSTED_CREDENTIAL_ACCESS",
    "CRITICAL",
    "Untrusted content is influencing credential access. This is blocked even when credential access exists elsewhere in the system.",
)
SECURITY_CONTROL_TAMPERING = flag(
    "SECURITY_CONTROL_TAMPERING",
    "CRITICAL",
    "The action attempts to modify security controls while influenced by untrusted content.",
)
POSSIBLE_SECRET_EXFILTRATION = flag(
    "POSSIBLE_SECRET_EXFILTRATION",
    "CRITICAL",
    "Data marked secret-derived is being sent to a network or another agent. This may be direct or encoded exfiltration.",
)
POSSIBLE_SIDE_CHANNEL = flag(
    "POSSIBLE_SIDE_CHANNEL",
    "HIGH",
    "Secret-derived data is being used in an externally observable action. Review for timing, size, destination, error, or encoding-based leakage.",
)
EXTERNAL_DATA_TRANSFER = flag(
    "EXTERNAL_DATA_TRANSFER",
    "MEDIUM",
    "Untrusted content is influencing outbound data transfer.",
)
IRREVERSIBLE_ACTION = flag(
    "IRREVERSIBLE_ACTION",
    "HIGH",
    "The requested action is marked irreversible and therefore requires stronger review.",
)
