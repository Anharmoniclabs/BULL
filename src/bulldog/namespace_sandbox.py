from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import os
import secrets
import shutil
import subprocess
import tempfile
from typing import Sequence

from .resource_limits import (
    ResourceBudget,
    apply_resource_budget,
)


@dataclass(frozen=True)
class SandboxAttestation:
    nonce: str
    pid: int
    no_new_privs: bool
    seccomp: bool
    seccomp_profile: str
    seccomp_rules: int
    landlock: bool
    landlock_abi: int
    network_interfaces: tuple[str, ...]
    network_isolated: bool
    python: str
    runtime_root: str


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    attestation: SandboxAttestation | None = None


class SandboxUnavailable(RuntimeError):
    pass


class SandboxAttestationError(RuntimeError):
    pass


def _detect_sandbox_python() -> str:
    override = os.environ.get("BULL_SANDBOX_PYTHON")
    candidates = []
    if override:
        candidates.append(str(override))
    candidates.extend(
        [
            "/usr/bin/python3.13",
            "/usr/bin/python3.12",
            "/usr/bin/python3.11",
            "/usr/bin/python3.10",
            "/usr/bin/python3",
        ]
    )
    for candidate in candidates:
        path = Path(candidate)
        if path.is_absolute() and path.is_file() and os.access(path, os.X_OK):
            if str(path).startswith(("/usr/", "/bin/")):
                return str(path)
    raise SandboxUnavailable(
        "no sandbox Python interpreter is available under /usr or /bin"
    )


class NamespaceSandbox:
    """BULL Linux namespace execution backend with live backend attestation."""

    def __init__(
        self,
        *,
        workspace_mount: str = "/workspace",
        seccomp_profile: str | None = None,
        sandbox_python: str | None = None,
        require_attestation: bool = True,
        runtime_root: str | Path | None = None,
    ):
        self.workspace_mount = workspace_mount
        self.seccomp_profile = (
            str(seccomp_profile).strip().lower()
            if seccomp_profile is not None
            else os.environ.get("BULL_SECCOMP_PROFILE", "compat").strip().lower()
        )
        if self.seccomp_profile not in {"compat", "strict"}:
            raise SandboxUnavailable(
                f"unsupported seccomp profile: {self.seccomp_profile}"
            )
        self.require_attestation = bool(require_attestation)

        required = ("unshare", "mount", "chroot", "bash")
        missing = [tool for tool in required if shutil.which(tool) is None]
        if missing:
            raise SandboxUnavailable(
                "missing sandbox tools: " + ", ".join(missing)
            )

        self.launcher = Path(__file__).with_name("_namespace_launcher.sh")
        if not self.launcher.exists():
            raise SandboxUnavailable(
                "missing namespace launcher: " + f"{self.launcher}"
            )

        self.sandbox_python = sandbox_python or _detect_sandbox_python()
        self.runtime_root = Path(
            runtime_root if runtime_root is not None else Path(__file__).resolve().parent
        ).resolve(strict=True)
        for required_file in ("seccomp_policy.py", "landlock_policy.py"):
            if not (self.runtime_root / required_file).is_file():
                raise SandboxUnavailable(
                    "trusted runtime root does not contain " + required_file
                )

    @staticmethod
    def _parse_attestation(
        raw: bytes,
        *,
        expected_nonce: str,
        expected_profile: str,
    ) -> SandboxAttestation:
        if not raw:
            raise SandboxAttestationError("sandbox emitted no backend attestation")
        if len(raw) > 16384:
            raise SandboxAttestationError("sandbox attestation exceeded size limit")

        try:
            lines = [line for line in raw.decode("utf-8").splitlines() if line.strip()]
            if len(lines) != 1:
                raise ValueError("expected exactly one attestation record")
            data = json.loads(lines[0])
        except Exception as exc:
            raise SandboxAttestationError(
                "invalid sandbox attestation: " + str(exc)
            ) from exc

        if data.get("format") != "bull-sandbox-attestation-v2":
            raise SandboxAttestationError("unknown sandbox attestation format")
        if not secrets.compare_digest(str(data.get("nonce", "")), expected_nonce):
            raise SandboxAttestationError("sandbox attestation nonce mismatch")
        if int(data.get("pid", -1)) != 1:
            raise SandboxAttestationError(
                "PID namespace attestation failed: bootstrap is not PID 1"
            )
        if data.get("no_new_privs") is not True:
            raise SandboxAttestationError("no_new_privs attestation failed")
        if data.get("seccomp") is not True:
            raise SandboxAttestationError("seccomp attestation failed")
        if str(data.get("seccomp_profile", "")) != expected_profile:
            raise SandboxAttestationError("seccomp profile attestation mismatch")
        if int(data.get("seccomp_rules", 0)) < 1:
            raise SandboxAttestationError("seccomp installed no rules")
        if expected_profile == "strict" and data.get("landlock") is not True:
            raise SandboxAttestationError("Landlock attestation failed")
        if expected_profile == "strict" and int(data.get("landlock_abi", 0)) < 1:
            raise SandboxAttestationError("Landlock ABI attestation failed")
        if data.get("network_isolated") is not True:
            raise SandboxAttestationError("network namespace attestation failed")
        if str(data.get("runtime_root", "")) != "/bull_runtime":
            raise SandboxAttestationError("trusted runtime mount attestation failed")

        interfaces = tuple(str(x) for x in data.get("network_interfaces", ()))
        if any(name != "lo" for name in interfaces):
            raise SandboxAttestationError(
                "network namespace exposes a non-loopback interface"
            )

        return SandboxAttestation(
            nonce=expected_nonce,
            pid=1,
            no_new_privs=True,
            seccomp=True,
            seccomp_profile=expected_profile,
            seccomp_rules=int(data["seccomp_rules"]),
            landlock=bool(data.get("landlock")),
            landlock_abi=int(data.get("landlock_abi", 0)),
            network_interfaces=interfaces,
            network_isolated=True,
            python=str(data.get("python", "")),
            runtime_root="/bull_runtime",
        )

    def run(
        self,
        command: Sequence[str],
        *,
        project_root: str | Path,
        writable: bool = True,
        timeout: float | None = 30.0,
        env: dict[str, str] | None = None,
        resource_budget: ResourceBudget | None = None,
    ) -> SandboxResult:
        if not command:
            raise ValueError("sandbox command cannot be empty")

        project_root = Path(project_root).resolve(strict=True)
        if not project_root.is_dir():
            raise ValueError("project_root must be a directory")

        rootfs = Path(tempfile.mkdtemp(prefix="bull_rootfs_", dir="/tmp"))
        mode = "rw" if writable else "ro"

        # Do not inherit agent/operator environment injection surfaces into the
        # trusted bootstrap. Only BULL-owned bindings may cross this boundary.
        outer_env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "HOME": "/nonexistent",
            "TMPDIR": "/tmp",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        if env:
            for key, value in env.items():
                key = str(key)
                if not key.startswith("BULL_"):
                    raise ValueError(
                        f"sandbox environment key is not host-approved: {key}"
                    )
                if key in {
                    "BULL_ATTEST_FD",
                    "BULL_ATTEST_NONCE",
                    "BULL_SECCOMP_PROFILE",
                }:
                    raise ValueError(
                        f"sandbox environment key is reserved: {key}"
                    )
                outer_env[key] = str(value)

        nonce = secrets.token_urlsafe(32)
        read_fd, write_fd = os.pipe()
        outer_env["BULL_ATTEST_FD"] = str(write_fd)
        outer_env["BULL_ATTEST_NONCE"] = nonce
        outer_env["BULL_SECCOMP_PROFILE"] = self.seccomp_profile

        preexec_fn = None
        if resource_budget is not None:
            def _apply_limits() -> None:
                apply_resource_budget(resource_budget)
            preexec_fn = _apply_limits

        proc = None
        try:
            try:
                proc = subprocess.run(
                    [
                        shutil.which("unshare") or "unshare",
                        "--user",
                        "--map-root-user",
                        "--mount",
                        "--pid",
                        "--fork",
                        "--net",
                        str(self.launcher),
                        str(rootfs),
                        str(project_root),
                        mode,
                        self.sandbox_python,
                        str(self.runtime_root),
                        *map(str, command),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                    env=outer_env,
                    preexec_fn=preexec_fn,
                    pass_fds=(write_fd,),
                )
            finally:
                os.close(write_fd)

            chunks = []
            total = 0
            while True:
                chunk = os.read(read_fd, 4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > 16384:
                    raise SandboxAttestationError(
                        "sandbox attestation exceeded size limit"
                    )
                chunks.append(chunk)
            raw_attestation = b"".join(chunks)

            attestation = None
            if self.require_attestation:
                attestation = self._parse_attestation(
                    raw_attestation,
                    expected_nonce=nonce,
                    expected_profile=self.seccomp_profile,
                )

            assert proc is not None
            return SandboxResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                attestation=attestation,
            )
        finally:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            shutil.rmtree(rootfs, ignore_errors=True)
