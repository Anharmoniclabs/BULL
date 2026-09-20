"""Cross-platform sandbox backend contract.

BULL has one portable policy model, but kernel enforcement is necessarily
platform native. A backend may only claim ``strict`` availability after it
proves its platform controls are installed. Unsupported platforms therefore
fail closed instead of silently executing a plain subprocess.

Current state:
- Linux: verified namespace/seccomp/Landlock backend.
- macOS: Seatbelt backend contract reserved; not implemented yet.
- Windows: AppContainer/Job Object backend contract reserved; not implemented
  yet.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import platform
from typing import Protocol, Sequence


class SandboxBackendUnavailable(RuntimeError):
    """Raised when a requested strict backend cannot be established."""


@dataclass(frozen=True)
class SandboxPolicy:
    """Platform-neutral containment intent.

    Native backends must translate this into their own enforcement mechanisms;
    they must not report strict availability if a requested policy dimension
    cannot be enforced.
    """

    workspace_writable: bool = False
    network_mode: str = "none"  # none | broker-only
    max_memory_bytes: int | None = None
    max_processes: int | None = None
    max_output_bytes: int = 1 << 20
    allow_secrets: bool = False

    def __post_init__(self) -> None:
        if self.network_mode not in {"none", "broker-only"}:
            raise ValueError("network_mode must be 'none' or 'broker-only'")
        if self.max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        if self.allow_secrets:
            raise ValueError(
                "generic sandbox policy cannot grant secrets; use the authenticated secret broker"
            )


@dataclass(frozen=True)
class BackendAttestation:
    """An honest, backend-specific report of controls actually installed."""

    platform: str
    backend: str
    strict: bool
    controls: tuple[str, ...]
    unavailable_reasons: tuple[str, ...] = ()
    details: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class SandboxBackend(Protocol):
    """Native backend interface implemented by strict platform enforcers."""

    platform_name: str
    backend_name: str

    def probe(self) -> BackendAttestation:
        """Report installed controls or why strict execution is unavailable."""

    def require_strict(self) -> BackendAttestation:
        """Return a strict attestation or raise SandboxBackendUnavailable."""

    def run(self, command: Sequence[str], **kwargs):
        """Execute under native enforcement; implemented by concrete backends."""


class _UnavailableNativeBackend:
    """Fail-closed placeholder for a backend not yet implemented."""

    platform_name = "unknown"
    backend_name = "unimplemented"
    required_controls: tuple[str, ...] = ()

    def probe(self) -> BackendAttestation:
        return BackendAttestation(
            platform=self.platform_name,
            backend=self.backend_name,
            strict=False,
            controls=(),
            unavailable_reasons=(
                "native strict sandbox backend is not implemented",
            ),
            details={"required_controls": self.required_controls},
        )

    def require_strict(self) -> BackendAttestation:
        report = self.probe()
        raise SandboxBackendUnavailable(
            f"BULL strict sandbox unavailable on {report.platform}: "
            + "; ".join(report.unavailable_reasons)
        )

    def run(self, command: Sequence[str], **kwargs):
        self.require_strict()
        raise AssertionError("require_strict must raise for an unavailable backend")


class MacOSSeatbeltBackend(_UnavailableNativeBackend):
    """Reserved macOS backend: Seatbelt plus parent resource supervision.

    This intentionally does not invoke sandbox-exec as a fake implementation.
    Production support requires a verified native helper and startup probes.
    """

    platform_name = "Darwin"
    backend_name = "seatbelt-unimplemented"
    required_controls = (
        "Seatbelt deny-by-default profile",
        "workspace/runtime path grants",
        "network deny or broker-only policy",
        "resource and process-tree supervision",
        "verified startup probes",
    )


class WindowsAppContainerBackend(_UnavailableNativeBackend):
    """Reserved Windows backend: AppContainer + Job Object + restricted token.

    Production support requires a native helper that creates an AppContainer,
    applies SID ACL grants, assigns a kill-on-close Job Object, and reports
    process-mitigation policy results.
    """

    platform_name = "Windows"
    backend_name = "appcontainer-unimplemented"
    required_controls = (
        "AppContainer or LPAC token",
        "per-run SID ACL grants",
        "Job Object kill-on-close and resource limits",
        "restricted token and process mitigations",
        "verified startup probes",
    )


class LinuxNamespaceBackend:
    """Adapter exposing BULL's existing verified Linux backend via this contract."""

    platform_name = "Linux"
    backend_name = "namespace-seccomp-landlock"

    def probe(self) -> BackendAttestation:
        from .namespace_sandbox import NamespaceSandbox, SandboxUnavailable

        try:
            sandbox = NamespaceSandbox(seccomp_profile="strict")
        except SandboxUnavailable as exc:
            return BackendAttestation(
                platform=self.platform_name,
                backend=self.backend_name,
                strict=False,
                controls=(),
                unavailable_reasons=(str(exc),),
            )
        return BackendAttestation(
            platform=self.platform_name,
            backend=self.backend_name,
            strict=True,
            controls=(
                "user namespace",
                "mount namespace",
                "PID namespace",
                "network namespace",
                "IPC namespace",
                "private mount propagation",
                "chroot rootfs",
                "no_new_privs",
                "strict seccomp",
                "Landlock required at run time",
                "nonce-bound backend attestation",
            ),
            details={
                "seccomp_profile": sandbox.seccomp_profile,
                "launcher": str(sandbox.launcher),
            },
        )

    def require_strict(self) -> BackendAttestation:
        report = self.probe()
        if not report.strict:
            raise SandboxBackendUnavailable(
                "BULL Linux strict sandbox unavailable: "
                + "; ".join(report.unavailable_reasons)
            )
        return report

    def run(self, command: Sequence[str], **kwargs):
        self.require_strict()
        from .namespace_sandbox import NamespaceSandbox

        return NamespaceSandbox(seccomp_profile="strict").run(command, **kwargs)


def select_backend(host: str | None = None) -> SandboxBackend:
    """Select the native backend for ``host`` (default: current system)."""
    host = host or platform.system()
    if host == "Linux":
        return LinuxNamespaceBackend()
    if host == "Darwin":
        return MacOSSeatbeltBackend()
    if host == "Windows":
        return WindowsAppContainerBackend()
    return _UnavailableNativeBackend()


def strict_backend_attestation(host: str | None = None) -> BackendAttestation:
    """Return strict backend state or fail closed on unsupported systems."""
    return select_backend(host).require_strict()
