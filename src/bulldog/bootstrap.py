from __future__ import annotations

"""Portable setup for the BULL command center.

Only local operator state is prepared here. Production certification and
platform-specific enforcement remain separate fail-closed gates.
"""

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import shutil
import socket


@dataclass(frozen=True)
class LaunchEnvironment:
    workspace: Path
    state_dir: Path
    audit_ledger: Path
    snapshot_root: Path
    host: str
    port: int
    url: str
    codespaces: bool
    clamav_available: bool
    qemu_available: bool
    kvm_available: bool
    unshare_available: bool

    @property
    def browser_open_supported(self) -> bool:
        return not self.codespaces and self.host in {"127.0.0.1", "localhost", "::1"}


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _state_dir(workspace: Path) -> Path:
    configured = os.environ.get("BULL_STATE_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".local" / "state" / "bull"
    digest = hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
    return _private_dir((base / f"{workspace.name or 'workspace'}-{digest}").resolve())


def _is_codespaces() -> bool:
    return os.environ.get("CODESPACES", "").lower() == "true" or bool(os.environ.get("CODESPACE_NAME"))


def _pick_port(host: str, preferred: int) -> int:
    if not 1 <= int(preferred) <= 65535:
        raise ValueError("console port must be between 1 and 65535")
    stop = min(int(preferred) + 20, 65536)
    for candidate in range(int(preferred), stop):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, candidate))
            except OSError:
                continue
            return candidate
    raise OSError(f"no available BULL console port from {preferred} through {stop - 1}")


def _url(port: int, codespaces: bool) -> str:
    if codespaces:
        name = os.environ.get("CODESPACE_NAME", "").strip()
        if name:
            domain = os.environ.get(
                "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev"
            ).strip()
            return f"https://{name}-{port}.{domain}/"
    return f"http://127.0.0.1:{port}/"


def prepare_launch_environment(
    workspace: str | Path,
    *,
    preferred_port: int = 11510,
    host: str | None = None,
) -> LaunchEnvironment:
    root = Path(workspace).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("BULL workspace must be a directory")

    codespaces = _is_codespaces()
    bind_host = host or ("0.0.0.0" if codespaces else "127.0.0.1")
    port = _pick_port(bind_host, preferred_port)
    state_dir = _state_dir(root)
    snapshot_root = _private_dir(state_dir / "snapshots")
    audit_ledger = state_dir / "audit.jsonl"

    os.environ.setdefault("BULL_STATE_DIR", str(state_dir))
    os.environ.setdefault("BULL_AUDIT_LEDGER", str(audit_ledger))
    os.environ.setdefault("BULL_SNAPSHOT_ROOT", str(snapshot_root))

    env_file = state_dir / "runtime.env"
    env_file.write_text(
        f"BULL_STATE_DIR={state_dir}\n"
        f"BULL_AUDIT_LEDGER={audit_ledger}\n"
        f"BULL_SNAPSHOT_ROOT={snapshot_root}\n",
        encoding="utf-8",
    )
    try:
        env_file.chmod(0o600)
    except OSError:
        pass

    kvm = Path("/dev/kvm")
    return LaunchEnvironment(
        workspace=root,
        state_dir=state_dir,
        audit_ledger=audit_ledger,
        snapshot_root=snapshot_root,
        host=bind_host,
        port=port,
        url=_url(port, codespaces),
        codespaces=codespaces,
        clamav_available=shutil.which("clamscan") is not None,
        qemu_available=shutil.which(os.environ.get("BULL_MICROVM_QEMU", "qemu-system-x86_64")) is not None,
        kvm_available=kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
        unshare_available=shutil.which("unshare") is not None,
    )


def summary_lines(env: LaunchEnvironment) -> tuple[str, ...]:
    mode = "Codespaces/private forwarded port" if env.codespaces else "local loopback"
    return (
        f"workspace: {env.workspace}",
        f"state: {env.state_dir}",
        f"console: {env.url}",
        f"bind: {env.host}:{env.port} ({mode})",
        f"ClamAV: {'ready' if env.clamav_available else 'unavailable'}",
        f"QEMU: {'ready' if env.qemu_available else 'unavailable'}",
        f"KVM: {'ready' if env.kvm_available else 'unavailable'}",
        f"Linux unshare: {'ready' if env.unshare_available else 'unavailable'}",
        "production status is evaluated separately; missing protections remain BLOCKED",
    )
