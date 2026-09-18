"""Container/namespace hardening checks for BULL's launcher.

Static audit of _namespace_launcher.sh plus runtime verification of the
three invariants that determine whether the containerizer actually isolates:

1. Mount propagation must be private, or every bind mount the launcher
   makes leaks onto the host mount table.
2. no_new_privs must be set, or setuid binaries inside the sandbox can
   regain privileges the drop was meant to remove.
3. Effective capability set must be empty for sandboxed workloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .socket_hardening import HardeningError


@dataclass(frozen=True)
class MountEntry:
    mount_point: str
    fstype: str
    optional_fields: tuple[str, ...]
    shared: bool


# Tokens a production-grade launcher must contain. audit_launcher_script
# reports one finding per missing token.
REQUIRED_LAUNCHER_TOKENS: tuple[str, ...] = (
    "set -euo pipefail",
    "--propagation private",
    "mount --make-rprivate",
    "nosuid",
    "nodev",
    "noexec",
)

_UNQUOTED_EXPANSION = re.compile(r"(?<!\")\$(?:ROOTFS|PROJECT|RUNTIME_ROOT)\b")


def parse_mountinfo(text: str) -> list[MountEntry]:
    """Parse /proc/*/mountinfo, marking entries with shared propagation."""
    entries: list[MountEntry] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or "-" not in parts:
            continue
        sep = parts.index("-")
        optional = tuple(parts[6:sep])
        entries.append(
            MountEntry(
                mount_point=parts[4],
                fstype=parts[sep + 1] if sep + 1 < len(parts) else "",
                optional_fields=optional,
                shared=any(f.startswith("shared:") for f in optional),
            )
        )
    return entries


def assert_no_shared_mounts(mountinfo_text: str) -> None:
    """Raise if ANY mount has shared propagation.

    Run this inside the namespace immediately after unshare; a shared:
    mount anywhere means bind mounts can propagate to the host.
    """
    leaks = [e for e in parse_mountinfo(mountinfo_text) if e.shared]
    if leaks:
        points = ", ".join(sorted(e.mount_point for e in leaks))
        raise HardeningError(
            f"shared-propagation mounts present, sandbox is not isolated: {points}"
        )


def assert_no_new_privs(status_text: str) -> None:
    """Raise unless NoNewPrivs: 1 in /proc/self/status content."""
    for line in status_text.splitlines():
        if line.startswith("NoNewPrivs:"):
            if line.split(":", 1)[1].strip() == "1":
                return
            raise HardeningError("no_new_privs is not set on this process")
    raise HardeningError("NoNewPrivs field missing from status")


def effective_capabilities(status_text: str) -> int:
    """Return the effective capability bitmask from a status text."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split(":", 1)[1].strip(), 16)
    raise HardeningError("CapEff field missing from status")


def assert_no_effective_caps(status_text: str) -> None:
    """Raise if the process holds any effective capability."""
    caps = effective_capabilities(status_text)
    if caps != 0:
        raise HardeningError(
            f"effective capabilities present in sandbox context: 0x{caps:x}"
        )


def assert_sandbox_invariants(proc_root: str | Path = "/proc") -> None:
    """Verify all three isolation invariants against a live proc tree."""
    proc_root = Path(proc_root)
    assert_no_shared_mounts((proc_root / "self" / "mountinfo").read_text("utf-8"))
    status = (proc_root / "self" / "status").read_text("utf-8")
    assert_no_new_privs(status)
    assert_no_effective_caps(status)


def audit_launcher_script(text: str) -> list[str]:
    """Static-audit the launcher shell script. Returns findings; empty = pass.

    Intended to be called from production_gate so the launcher contract is
    re-verified on every release, not just by the test suite.
    """
    findings: list[str] = []
    for token in REQUIRED_LAUNCHER_TOKENS:
        if token not in text:
            findings.append(f"launcher missing required token: {token!r}")

    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _UNQUOTED_EXPANSION.search(line):
            findings.append(
                f"line {lineno}: unquoted path expansion risks word-splitting: "
                f"{stripped[:80]}"
            )
        if "LD_PRELOAD" in stripped and "unset" not in stripped:
            findings.append(
                f"line {lineno}: LD_PRELOAD referenced without unset; "
                "host preload injection may cross the namespace boundary"
            )
    return findings
