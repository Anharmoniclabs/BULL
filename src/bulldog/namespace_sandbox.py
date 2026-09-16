from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
from typing import Sequence

from .resource_limits import (
    ResourceBudget,
    apply_resource_budget,
)


@dataclass(frozen=True)
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str


class SandboxUnavailable(RuntimeError):
    pass


class NamespaceSandbox:
    """
    BULL Linux namespace execution backend.

    Kernel-enforced isolation:
      - user namespace
      - mount namespace
      - PID namespace
      - network namespace
      - private tmpfs root
      - project-only bind mount
      - optional read-only project mount
      - private /tmp
      - no_new_privs
      - seccomp
      - optional child rlimits

    Network starts disconnected.
    """

    def __init__(
        self,
        *,
        workspace_mount: str = "/workspace",
    ):
        self.workspace_mount = workspace_mount

        required = (
            "unshare",
            "mount",
            "chroot",
            "bash",
        )

        missing = [
            tool
            for tool in required
            if shutil.which(tool) is None
        ]

        if missing:
            raise SandboxUnavailable(
                "missing sandbox tools: " + ", ".join(missing)
            )

        self.launcher = Path(__file__).with_name(
            "_namespace_launcher.sh"
        )

        if not self.launcher.exists():
            raise SandboxUnavailable(
                "missing namespace launcher: "
                f"{self.launcher}"
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
            raise ValueError(
                "sandbox command cannot be empty"
            )

        project_root = Path(project_root).resolve(strict=True)

        if not project_root.is_dir():
            raise ValueError(
                "project_root must be a directory"
            )

        rootfs = Path(
            tempfile.mkdtemp(
                prefix="bull_rootfs_",
                dir="/tmp",
            )
        )

        mode = "rw" if writable else "ro"
        outer_env = os.environ.copy()

        if env:
            outer_env.update(
                {
                    str(key): str(value)
                    for key, value in env.items()
                }
            )

        preexec_fn = None
        if resource_budget is not None:
            # Limits are applied in the unshare child, so the BULL host
            # process itself keeps its normal resource envelope.
            def _apply_limits() -> None:
                apply_resource_budget(resource_budget)

            preexec_fn = _apply_limits

        try:
            proc = subprocess.run(
                [
                    "unshare",
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
                    *map(str, command),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                env=outer_env,
                preexec_fn=preexec_fn,
            )

            return SandboxResult(
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        finally:
            shutil.rmtree(
                rootfs,
                ignore_errors=True,
            )
