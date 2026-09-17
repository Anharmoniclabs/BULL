from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import time


class WorkspaceLimitViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkspaceBudget:
    """Hard admission limits for untrusted project trees before sandboxing."""

    max_files: int = 50_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_file_bytes: int = 128 * 1024 * 1024
    max_depth: int = 32
    max_path_bytes: int = 4096
    manifest_timeout_seconds: float = 20.0
    snapshot_timeout_seconds: float = 30.0
    malware_scan_timeout_seconds: float = 60.0
    snapshot_min_free_bytes: int = 512 * 1024 * 1024

    @classmethod
    def from_environment(cls) -> "WorkspaceBudget":
        defaults = cls()

        def _integer(name: str, default: int) -> int:
            raw = os.environ.get(name)
            return default if raw is None else int(raw)

        def _seconds(name: str, default: float) -> float:
            raw = os.environ.get(name)
            return default if raw is None else float(raw)

        budget = cls(
            max_files=_integer("BULL_MAX_WORKSPACE_FILES", defaults.max_files),
            max_total_bytes=_integer(
                "BULL_MAX_WORKSPACE_BYTES", defaults.max_total_bytes
            ),
            max_file_bytes=_integer(
                "BULL_MAX_WORKSPACE_FILE_BYTES", defaults.max_file_bytes
            ),
            max_depth=_integer("BULL_MAX_WORKSPACE_DEPTH", defaults.max_depth),
            max_path_bytes=_integer(
                "BULL_MAX_WORKSPACE_PATH_BYTES", defaults.max_path_bytes
            ),
            manifest_timeout_seconds=_seconds(
                "BULL_MANIFEST_TIMEOUT_SECONDS",
                defaults.manifest_timeout_seconds,
            ),
            snapshot_timeout_seconds=_seconds(
                "BULL_SNAPSHOT_TIMEOUT_SECONDS",
                defaults.snapshot_timeout_seconds,
            ),
            malware_scan_timeout_seconds=_seconds(
                "BULL_MALWARE_SCAN_TIMEOUT_SECONDS",
                defaults.malware_scan_timeout_seconds,
            ),
            snapshot_min_free_bytes=_integer(
                "BULL_SNAPSHOT_MIN_FREE_BYTES", defaults.snapshot_min_free_bytes
            ),
        )
        budget.validate()
        return budget

    def validate(self) -> None:
        integer_fields = (
            self.max_files,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_depth,
            self.max_path_bytes,
            self.snapshot_min_free_bytes,
        )
        if any(value < 1 for value in integer_fields):
            raise WorkspaceLimitViolation("workspace limits must be positive")
        if self.max_file_bytes > self.max_total_bytes:
            raise WorkspaceLimitViolation(
                "maximum file size cannot exceed maximum workspace size"
            )
        if min(
            self.manifest_timeout_seconds,
            self.snapshot_timeout_seconds,
            self.malware_scan_timeout_seconds,
        ) <= 0:
            raise WorkspaceLimitViolation("workspace timeouts must be positive")


def deadline_after(seconds: float) -> float:
    return time.monotonic() + float(seconds)


def require_before(deadline: float, phase: str) -> None:
    if time.monotonic() > deadline:
        raise WorkspaceLimitViolation(f"{phase} exceeded wall-clock budget")


def production_snapshot_root() -> Path:
    raw = os.environ.get("BULL_SNAPSHOT_ROOT", "").strip()
    if not raw:
        raise WorkspaceLimitViolation(
            "production snapshot scratch root is not configured"
        )
    root = Path(raw).resolve(strict=True)
    if not root.is_dir():
        raise WorkspaceLimitViolation("snapshot scratch root is not a directory")
    return root
