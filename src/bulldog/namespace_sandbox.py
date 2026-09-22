from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import json
from pathlib import Path
import os
import selectors
import signal
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Sequence

from .cgroup_scope import CgroupV2Scope
from .resource_limits import ResourceBudget, apply_resource_budget


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
    bootstrap_complete_ns: int = 0


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    attestation: SandboxAttestation | None = None
    sandbox_setup_ms: float | None = None
    workload_to_reap_ms: float | None = None


class SandboxUnavailable(RuntimeError):
    pass


class SandboxAttestationError(RuntimeError):
    pass


class SandboxOutputLimitExceeded(RuntimeError):
    pass


# Maximum retained and permitted output per stream. This is intentionally
# separate from the child cgroup budget: pipes are buffered by the host.
DEFAULT_MAX_OUTPUT_BYTES = 1 << 20  # 1 MiB per stdout/stderr stream
_OUTPUT_LIMIT_MARKER = b"\n[BULL: output limit exceeded; sandbox process group terminated]\n"


def _terminate_process_group(proc: subprocess.Popen[bytes]) -> None:
    """Terminate the sandbox launcher and all descendants, best-effort."""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _run_bounded(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout: float | None,
    pass_fds: tuple[int, ...],
    preexec_fn,
    max_output_bytes: int,
) -> tuple[int, str, str]:
    """Run argv with bounded concurrent stdout/stderr capture.

    A single stream exceeding ``max_output_bytes`` terminates the entire
    process group. This prevents a sandbox workload from exhausting host
    memory through PIPE buffering while retaining a useful diagnostic prefix.
    """
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=env,
        preexec_fn=preexec_fn,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
    selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = False
    deadline = None if timeout is None else __import__("time").monotonic() + timeout

    try:
        while selector.get_map():
            if deadline is not None and __import__("time").monotonic() >= deadline:
                _terminate_process_group(proc)
                raise subprocess.TimeoutExpired(argv, timeout)

            events = selector.select(
                None if deadline is None else max(0.0, deadline - __import__("time").monotonic())
            )
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue

                buffer = buffers[key.data]
                remaining = max_output_bytes - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    exceeded = True
                    _terminate_process_group(proc)

            if exceeded:
                # Drain pipes after group termination so the child cannot block
                # during teardown and selector registrations close cleanly.
                continue

        returncode = proc.wait()
    finally:
        if proc.poll() is None:
            _terminate_process_group(proc)
        selector.close()

    stdout = bytes(buffers["stdout"])
    stderr = bytes(buffers["stderr"])
    if exceeded:
        # Place the marker on stderr even when stdout triggered the cap, so a
        # caller that logs only error output still sees why execution stopped.
        stderr = (stderr[:max_output_bytes - len(_OUTPUT_LIMIT_MARKER)] + _OUTPUT_LIMIT_MARKER)
    return (
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _detect_sandbox_python() -> str:
    override = os.environ.get("BULL_SANDBOX_PYTHON")
    candidates = []
    if override:
        candidates.append(str(override))
    candidates.extend([
        "/usr/bin/python3.13",
        "/usr/bin/python3.12",
        "/usr/bin/python3.11",
        "/usr/bin/python3.10",
        "/usr/bin/python3",
    ])
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
            raise SandboxUnavailable("missing sandbox tools: " + ", ".join(missing))

        self.launcher = Path(__file__).with_name("_namespace_launcher.sh")
        if not self.launcher.exists():
            raise SandboxUnavailable("missing namespace launcher: " + str(self.launcher))

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
            raise SandboxAttestationError("invalid sandbox attestation: " + str(exc)) from exc

        if data.get("format") != "bull-sandbox-attestation-v2":
            raise SandboxAttestationError("unknown sandbox attestation format")
        if not secrets.compare_digest(str(data.get("nonce", "")), expected_nonce):
            raise SandboxAttestationError("sandbox attestation nonce mismatch")
        if int(data.get("pid", -1)) != 1:
            raise SandboxAttestationError("PID namespace attestation failed: bootstrap is not PID 1")
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
            bootstrap_complete_ns=int(data.get("bootstrap_complete_ns", 0)),
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
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> SandboxResult:
        if not command:
            raise ValueError("sandbox command cannot be empty")
        project_root = Path(project_root).resolve(strict=True)
        if not project_root.is_dir():
            raise ValueError("project_root must be a directory")

        rootfs = Path(tempfile.mkdtemp(prefix="bull_rootfs_", dir="/tmp"))
        mode = "rw" if writable else "ro"
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
                    raise ValueError(f"sandbox environment key is not host-approved: {key}")
                if key in {"BULL_ATTEST_FD", "BULL_ATTEST_NONCE", "BULL_SECCOMP_PROFILE", "BULL_GO_FD"}:
                    raise ValueError(f"sandbox environment key is reserved: {key}")
                outer_env[key] = str(value)

        nonce = secrets.token_urlsafe(32)
        read_fd, write_fd = os.pipe()
        go_read_fd, go_write_fd = os.pipe()
        outer_env["BULL_ATTEST_FD"] = str(write_fd)
        outer_env["BULL_ATTEST_NONCE"] = nonce
        outer_env["BULL_SECCOMP_PROFILE"] = self.seccomp_profile
        outer_env["BULL_GO_FD"] = str(go_read_fd)

        # BULL-ATTEST-PREEXEC-GATE-V1
        # The bootstrap cannot exec the workload until this host reader
        # consumes and validates the nonce-bound attestation.
        attestation_state = {
            "raw": b"",
            "attestation": None,
            "error": None,
        }

        def _attestation_gate_reader() -> None:
            buffer = bytearray()
            try:
                while b"\n" not in buffer:
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) > 16384:
                        raise SandboxAttestationError(
                            "sandbox attestation exceeded size limit"
                        )

                raw = bytes(buffer)
                attestation_state["raw"] = raw

                if self.require_attestation:
                    attestation_state["attestation"] = self._parse_attestation(
                        raw,
                        expected_nonce=nonce,
                        expected_profile=self.seccomp_profile,
                    )

                os.write(go_write_fd, b"1")
            except BaseException as exc:
                attestation_state["error"] = exc
            finally:
                try:
                    os.close(go_write_fd)
                except OSError:
                    pass

        attestation_thread = threading.Thread(
            target=_attestation_gate_reader,
            name="bull-attestation-gate",
            daemon=True,
        )
        attestation_thread.start()

        scope = None
        if resource_budget is not None:
            scope = CgroupV2Scope.from_environment(
                memory_bytes=int(resource_budget.memory_bytes),
                processes=int(resource_budget.processes),
                cpu_quota_us=100_000,
                name_prefix="bull-workload",
            )
        context = scope if scope is not None else nullcontext(None)

        proc = None
        try:
            with context as active_scope:
                preexec_fn = None
                if resource_budget is not None:
                    def _apply_limits() -> None:
                        apply_resource_budget(resource_budget)
                        if active_scope is not None:
                            active_scope.attach_current()
                    preexec_fn = _apply_limits

                started_ns = time.monotonic_ns()
                try:
                    returncode, stdout, stderr = _run_bounded(
                        [
                            shutil.which("unshare") or "unshare",
                            "--user",
                            "--map-root-user",
                            "--mount",
                            "--pid",
                            "--fork",
                            "--net",
                            "--ipc",
                            str(self.launcher),
                            str(rootfs),
                            str(project_root),
                            mode,
                            self.sandbox_python,
                            str(self.runtime_root),
                            *map(str, command),
                        ],
                        env=outer_env,
                        timeout=timeout,
                        preexec_fn=preexec_fn,
                        pass_fds=(write_fd, go_read_fd),
                        max_output_bytes=max_output_bytes,
                    )
                    reaped_ns = time.monotonic_ns()
                finally:
                    os.close(write_fd)

            attestation_thread.join(timeout=2.0)
            if attestation_thread.is_alive():
                raise SandboxAttestationError(
                    "timed out waiting for pre-exec sandbox attestation"
                )
            if attestation_state["error"] is not None:
                error = attestation_state["error"]
                if isinstance(error, BaseException):
                    raise error
                raise SandboxAttestationError(str(error))

            attestation = attestation_state["attestation"]

            boundary = attestation.bootstrap_complete_ns if attestation else 0
            if boundary and not started_ns <= boundary <= reaped_ns:
                raise SandboxAttestationError("invalid bootstrap timing evidence")
            return SandboxResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                attestation=attestation,
                sandbox_setup_ms=(boundary - started_ns) / 1e6 if boundary else None,
                workload_to_reap_ms=(reaped_ns - boundary) / 1e6 if boundary else None,
            )
        finally:
            for fd in (read_fd, write_fd, go_read_fd, go_write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            shutil.rmtree(rootfs, ignore_errors=True)
