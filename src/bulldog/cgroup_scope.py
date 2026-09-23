from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import secrets
import time


class CgroupUnavailable(RuntimeError):
    pass


@dataclass
class CgroupV2Scope:
    parent: Path
    memory_bytes: int
    processes: int
    cpu_quota_us: int
    cpu_period_us: int = 100_000
    name_prefix: str = "bull"

    def __post_init__(self) -> None:
        self.parent = Path(self.parent).resolve(strict=True)
        if not (Path("/sys/fs/cgroup") / "cgroup.controllers").exists():
            raise CgroupUnavailable("cgroup v2 is unavailable")
        if not os.access(self.parent, os.W_OK | os.X_OK):
            raise CgroupUnavailable("delegated cgroup parent is not writable")
        self.path: Path | None = None

    @classmethod
    def from_environment(
        cls,
        *,
        memory_bytes: int,
        processes: int,
        cpu_quota_us: int = 100_000,
        name_prefix: str = "bull",
    ) -> "CgroupV2Scope | None":
        raw = os.environ.get("BULL_CGROUP_PARENT", "").strip()
        if not raw:
            return None
        return cls(
            parent=Path(raw),
            memory_bytes=int(memory_bytes),
            processes=int(processes),
            cpu_quota_us=int(cpu_quota_us),
            name_prefix=name_prefix,
        )

    def __enter__(self) -> "CgroupV2Scope":
        suffix = f"{os.getpid()}-{time.time_ns()}-{secrets.token_hex(4)}"
        path = self.parent / f"{self.name_prefix}-{suffix}"
        path.mkdir(mode=0o700)
        self.path = path
        try:
            self._write("memory.max", str(int(self.memory_bytes)))
            self._write("pids.max", str(int(self.processes)))
            self._write(
                "cpu.max",
                f"{int(self.cpu_quota_us)} {int(self.cpu_period_us)}",
            )
        except BaseException:
            # __exit__ is not invoked when __enter__ fails.
            self.__exit__(None, None, None)
            raise
        return self

    def _write(self, name: str, value: str) -> None:
        if self.path is None:
            raise CgroupUnavailable("cgroup scope has not been entered")
        target = self.path / name
        try:
            target.write_text(str(value), encoding="ascii")
        except OSError as exc:
            raise CgroupUnavailable(
                f"unable to configure cgroup {name}: {exc}"
            ) from exc

    def attach_current(self) -> None:
        if self.path is None:
            raise CgroupUnavailable("cgroup scope has not been entered")
        self._write("cgroup.procs", str(os.getpid()))

    def __exit__(self, exc_type, exc, tb) -> bool:
        path = self.path
        self.path = None
        if path is None:
            return False
        kill_file = path / "cgroup.kill"
        if kill_file.exists():
            try:
                kill_file.write_text("1", encoding="ascii")
            except OSError:
                pass
        for _ in range(20):
            try:
                path.rmdir()
                break
            except OSError:
                time.sleep(0.01)
        return False
