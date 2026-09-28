"""Managed agent sessions: run Codex or Claude Code with every native tool contained.

Connected-tools mode (``bull-mcp`` registered in an ordinary client) governs
only the calls that go through BULL. A managed session instead launches the
whole client process tree inside a checked Linux boundary:

* new mount, network, PID, IPC, UTS and cgroup namespaces;
* a root file system built from an allowlist (system directories, the client
  and BULL installations, all read-only), so the operator's home, SSH and cloud
  keys, Docker socket, BULL authority state and other local IPC do not exist;
* a disposable copy of the project as the only writable work area;
* no network interface except loopback. The model provider is reached through
  the inference relay, which tunnels only to the profile's provider hosts;
* a dedicated agent account with no supplementary groups, no capabilities,
  ``no_new_privs``, a seccomp profile and resource limits;
* read-only, system-level client configuration naming only BULL's MCP server.

The client's native shell, file tools, sub-agents and any MCP servers it starts
run inside the same boundary. That is contained native execution: they can
change the disposable workspace, talk to the provider and call BULL, and
nothing else. Changes return to the real project only through
``bull agent export``, which shows a patch and refuses host-executed paths.

The launcher needs root (via sudo) to create namespaces and switch to the agent
account. It never gives root to the workload.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import difflib
import errno
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback

from .client_profiles import PROFILES

SESSION_FORMAT = "bull-managed-session-v1"
AGENT_HOME = "/home/agent"
WORKSPACE = "/workspace"
RELAY_PORT = 3128
# Copied into the workspace only on request: common credential and key files.
DEFAULT_EXCLUDES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".aws",
    ".ssh",
    ".gnupg",
)
# Paths the operator's own tools execute or trust: never exported by default.
PROTECTED = (
    ".git",
    ".git/*",
    ".gitmodules",
    ".gitattributes",
    ".github/*",
    ".gitlab-ci.yml",
    ".claude/*",
    ".codex/*",
    ".mcp.json",
    ".vscode/*",
    ".idea/*",
    ".envrc",
    ".npmrc",
    ".pypirc",
    "*.pth",
    ".pre-commit-config.yaml",
    ".husky/*",
    "Makefile",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
)
MAX_EXPORT_FILE = 8 * 1024 * 1024
SYSTEM_READONLY = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
ETC_MASKED = {
    "bull",
    "claude-code",
    "codex",
    "shadow",
    "shadow-",
    "gshadow",
    "gshadow-",
    "sudoers",
    "sudoers.d",
    "ssh",
    "security",
    "machine-id",
    "docker",
    "containerd",
    "credstore",
    "credstore.encrypted",
    "wireguard",
    "letsencrypt",
}
DEVICES = ("null", "zero", "full", "random", "urandom", "tty")


class LaunchBlocked(RuntimeError):
    """A required isolation control is missing; nothing weaker is attempted."""


# ---------------------------------------------------------------- plan / checks


def _owner_safe(path: Path, untrusted_uid: int) -> bool:
    """True if neither ``path`` nor an ancestor is writable by untrusted_uid."""
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid == untrusted_uid:
            return False
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_mode & 0o002 and not sticky_root:
            return False
    return True


def _install_root(binary: Path) -> Path:
    """Directory holding a client's whole package (node_modules parent, venv...)."""
    real = binary.resolve(strict=True)
    for parent in real.parents:
        if parent.name == "node_modules":
            return parent.parent
    return real.parent


def _interpreter(binary: Path) -> Path | None:
    with open(binary.resolve(strict=True), "rb") as handle:
        first = handle.readline(256)
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode("utf-8", "replace").split()
    if not words:
        return None
    if Path(words[0]).name == "env" and len(words) > 1:
        found = shutil.which(words[1])
        return Path(found).resolve() if found else None
    return Path(words[0]).resolve()


def runtime_roots(binary: Path) -> list[Path]:
    """Read-only roots the client needs: its package and its interpreter prefix."""
    roots = [_install_root(binary)]
    interp = _interpreter(binary)
    if interp is not None:
        roots.append(interp.parent.parent if interp.parent.name == "bin" else interp.parent)
    return roots


def bull_roots() -> list[Path]:
    """This BULL installation: the environment prefix and the package source."""
    package = Path(__file__).resolve().parent
    return [Path(sys.prefix).resolve(), package.parent]


def _collapse(paths) -> list[Path]:
    """Drop paths already covered by another root or by the system binds."""
    system = [Path(p) for p in SYSTEM_READONLY]
    chosen: list[Path] = []
    for path in sorted({Path(p).resolve() for p in paths}, key=lambda p: (len(p.parts), str(p))):
        covered = [*system, *chosen]
        if any(path == c or c in path.parents for c in covered):
            continue
        chosen.append(path)
    return chosen


def build_plan(args) -> dict:
    profile = PROFILES[args.client]
    binary = Path(args.client_binary or shutil.which(profile.binary) or "")
    if not binary.is_absolute() or not binary.exists():
        raise LaunchBlocked(f"{profile.binary} is not installed or --client-binary is not absolute")
    agent = pwd.getpwnam(args.agent_user)
    bull_mcp = Path(args.bull_mcp or Path(sys.prefix) / "bin" / "bull-mcp")
    hosts = tuple(dict.fromkeys((*profile.provider_hosts, *args.provider_host)))
    ro_roots = _collapse(
        [*runtime_roots(binary), *bull_roots(), *(Path(p) for p in args.extra_ro)]
    )
    return {
        "format": SESSION_FORMAT,
        "client": profile.name,
        "client_binary": str(binary),
        "client_args": list(args.client_args),
        "agent_uid": agent.pw_uid,
        "agent_gid": agent.pw_gid,
        "agent_user": agent.pw_name,
        "agent_home": agent.pw_dir,
        "project": str(Path(args.project).resolve(strict=True)),
        "authority_socket": str(args.authority_socket),
        "authority_uid": args.authority_uid,
        "bull_mcp": str(bull_mcp),
        "provider_hosts": list(hosts),
        "readonly_roots": [str(p) for p in ro_roots],
        "upstream_proxy": args.upstream_proxy,
        "ca_bundle": str(args.ca_bundle) if args.ca_bundle else None,
        "resource_mode": args.resource_mode,
        "cgroup_parent": str(args.cgroup_parent) if args.cgroup_parent else None,
        "copy_credentials": bool(args.copy_credentials),
        "api_key_file": str(args.api_key_file) if args.api_key_file else None,
        "excludes": list(DEFAULT_EXCLUDES if not args.no_default_excludes else ())
        + list(args.exclude),
        "max_seconds": args.max_seconds,
        "operator_uid": int(os.environ.get("SUDO_UID", "-1")),
    }


def preflight(plan: dict) -> list[dict]:
    checks: list[dict] = []

    def check(name, ok, detail):
        checks.append({"check": name, "status": "PASS" if ok else "BLOCKED", "detail": detail})

    check("linux", platform.system() == "Linux", platform.system())
    check(
        "absolute_paths",
        all(Path(plan[k]).is_absolute() for k in ("authority_socket", "bull_mcp", "client_binary")),
        "authority socket, connector and client must be absolute paths",
    )
    check("launcher_root", os.geteuid() == 0, "namespaces and account switch need sudo")
    uid = plan["agent_uid"]
    check(
        "dedicated_agent_account",
        uid > 0 and uid not in (plan["authority_uid"], plan["operator_uid"]),
        "agent must be a separate non-root account, not the authority or operator",
    )
    try:
        subprocess.run(
            ["unshare", "--mount", "--net", "--pid", "--ipc", "--uts", "--fork", "true"],
            check=True, capture_output=True, timeout=20,
        )
        ns_ok, ns_detail = True, "mount, net, pid, ipc and uts namespaces"
    except (OSError, subprocess.SubprocessError) as exc:
        ns_ok, ns_detail = False, f"namespaces unavailable: {exc}"
    check("namespaces", ns_ok, ns_detail)
    try:
        from . import seccomp_policy  # noqa: F401  (loads libseccomp)

        check("seccomp", True, "libseccomp loaded")
    except Exception as exc:  # SeccompUnavailable and loader errors
        check("seccomp", False, str(exc))
    sock = Path(plan["authority_socket"])
    try:
        info = sock.lstat()
        parent = sock.parent.stat()
        ok = (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == plan["authority_uid"]
            and parent.st_uid == plan["authority_uid"]
            and not parent.st_mode & 0o002
        )
        check("authority_socket", ok, str(sock))
    except OSError as exc:
        check("authority_socket", False, str(exc))
    bull_mcp = Path(plan["bull_mcp"])
    check(
        "bull_mcp_trusted",
        bull_mcp.is_file() and os.access(bull_mcp, os.X_OK) and _owner_safe(bull_mcp, uid),
        "connector must exist and be unwritable by the agent account",
    )
    binary = Path(plan["client_binary"])
    check(
        "client_binary_trusted",
        _owner_safe(binary.resolve(), uid),
        "client installation must be unwritable by the agent account",
    )
    project = Path(plan["project"])
    check("project", project.is_dir(), str(project))
    if plan["resource_mode"] == "cgroup":
        parent = Path(plan["cgroup_parent"] or "")
        ok = (
            Path("/sys/fs/cgroup/cgroup.controllers").is_file()
            and parent.is_dir()
            and (parent / "cgroup.procs").exists()
        )
        check("cgroup_limits", ok, f"delegated cgroup v2 parent: {parent}")
    else:
        check(
            "cgroup_limits",
            True,
            "operator chose rlimit-only: per-process limits, no memory/CPU ceiling",
        )
    if plan["ca_bundle"]:
        check("ca_bundle", Path(plan["ca_bundle"]).is_file(), plan["ca_bundle"])
    return checks


# ----------------------------------------------------------- session creation


def _excluded(relative: str, patterns) -> bool:
    parts = relative.split("/")
    return any(fnmatch.fnmatch(part, pat) for part in parts for pat in patterns)


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root: Path, excludes) -> dict[str, str]:
    """sha256 of every regular file under root (relative paths), excluding patterns."""
    result = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [
            d for d in dirnames
            if not _excluded(os.path.normpath(os.path.join(rel_dir, d)), excludes)
        ]
        for name in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, name))
            full = Path(dirpath) / name
            if _excluded(rel, excludes) or not stat.S_ISREG(full.lstat().st_mode):
                continue
            result[rel] = _digest(full)
    return result


def _chown_tree(root: Path, uid: int, gid: int) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.lchown(dirpath, uid, gid)
        for name in (*dirnames, *filenames):
            os.lchown(os.path.join(dirpath, name), uid, gid)


def copy_agent_credential(agent_home: Path, relative: str, target: Path, uid: int) -> bool:
    """Copy the agent's own provider login, never a file it merely points at.

    This runs as root on a path the agent account controls, so a symlinked
    directory could otherwise make root copy a root-only file into the session.
    """
    base = agent_home.resolve()
    source = (agent_home / relative).resolve()
    if not source.is_relative_to(base) or not source.is_file():
        return False
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if info.st_uid != uid or not stat.S_ISREG(info.st_mode) or info.st_size > 1 << 20:
            return False
        data = handle.read()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    os.chmod(target, 0o600)
    return True


def _strip_git_credentials(workspace: Path) -> None:
    """Remote URLs sometimes embed tokens (https://TOKEN@host/...)."""
    config = workspace / ".git" / "config"
    if config.is_file() and not config.is_symlink():
        text = config.read_text(errors="replace")
        config.write_text(re.sub(r"(://)[^/@\s]+@", r"\1", text))


def prepare_session(plan: dict, sessions_root: Path) -> Path:
    sessions_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sessions_root, 0o700)
    session = sessions_root / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4))
    session.mkdir(mode=0o700)
    uid, gid = plan["agent_uid"], plan["agent_gid"]
    project = Path(plan["project"])
    workspace = session / "workspace"
    shutil.copytree(
        project,
        workspace,
        symlinks=True,
        ignore=lambda d, names: [
            n for n in names
            if _excluded(os.path.normpath(os.path.relpath(os.path.join(d, n), project)), plan["excludes"])
        ],
    )
    _strip_git_credentials(workspace)
    _chown_tree(workspace, uid, gid)
    manifest = snapshot(project, plan["excludes"])
    (session / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    home = session / "home"
    home.mkdir(mode=0o700)
    profile = PROFILES[plan["client"]]
    if plan["copy_credentials"]:
        for relative in profile.credential_files:
            copy_agent_credential(Path(plan["agent_home"]), relative, home / relative, uid)
    if plan["client"] == "codex":
        (home / ".codex").mkdir(exist_ok=True)
    _chown_tree(home, uid, gid)
    etc = session / "etc"
    for relative, content in profile.managed_files(
        plan["bull_mcp"], plan["authority_socket"], plan["authority_uid"]
    ).items():
        target = etc / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        os.chmod(target, 0o444)
    relay = session / "relay"
    relay.mkdir(mode=0o711)
    (session / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True))
    return session


# ------------------------------------------------------------ mount primitives

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
MNT_DETACH = 2
_PIVOT_ROOT = {"x86_64": 155, "aarch64": 41}


def _mount(source, target, fstype=None, flags=0, data=None) -> None:
    rc = _libc.mount(
        None if source is None else str(source).encode(),
        str(target).encode(),
        None if fstype is None else fstype.encode(),
        ctypes.c_ulong(flags),
        None if data is None else data.encode(),
    )
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, f"mount {source} -> {target}: {os.strerror(code)}")


def _bind(source: Path, target: Path, *, readonly: bool, device: bool = False) -> None:
    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=True)
    _mount(source, target, flags=MS_BIND)
    extra = MS_RDONLY if readonly else 0
    # nodev everywhere except the few device nodes deliberately provided.
    extra |= 0 if device else MS_NODEV
    _mount(None, target, flags=MS_REMOUNT | MS_BIND | MS_NOSUID | extra)


def _loopback_up() -> None:
    SIOCGIFFLAGS, SIOCSIFFLAGS = 0x8913, 0x8914
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        request = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
        flags = struct.unpack("16sH14s", fcntl.ioctl(s, SIOCGIFFLAGS, request))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", flags | 0x1 | 0x40, b"\0" * 14))


def _prctl_no_new_privs() -> None:
    if _libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")


def _become_agent(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    _prctl_no_new_privs()
    if os.getuid() != uid or os.geteuid() != uid:
        raise RuntimeError("failed to switch to the agent account")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:  # pragma: no cover - would be a kernel/runtime defect
        raise RuntimeError("privilege could be regained")


def _limits() -> None:
    for limit, value in (
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NPROC, 2048),
        (resource.RLIMIT_NOFILE, 65536),
        (resource.RLIMIT_FSIZE, 4 << 30),
    ):
        try:
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            soft, hard = resource.getrlimit(limit)
            resource.setrlimit(limit, (min(value, hard), min(value, hard)))


# ------------------------------------------------------ stage 2 (in namespaces)


def _build_root(session: Path, plan: dict) -> Path:
    root = session / "root"
    root.mkdir(mode=0o755, exist_ok=True)
    _mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=64m")
    for name in SYSTEM_READONLY:
        source = Path(name)
        if source.is_symlink():
            (root / name.lstrip("/")).symlink_to(os.readlink(source))
        elif source.is_dir():
            _bind(source, root / name.lstrip("/"), readonly=True)
    # /etc: each host entry read-only, minus secrets and client configuration,
    # plus the session's managed client files.
    etc = root / "etc"
    etc.mkdir()
    _mount("tmpfs", etc, "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=4m")
    for entry in sorted(os.listdir("/etc")):
        if entry in ETC_MASKED:
            continue
        source = Path("/etc") / entry
        if source.is_symlink():
            (etc / entry).symlink_to(os.readlink(source))
        elif source.exists():
            try:
                _bind(source, etc / entry, readonly=True)
            except OSError:
                continue  # Unreadable special entries are simply absent.
    for managed in sorted((session / "etc").rglob("*")):
        if managed.is_file():
            _bind(managed, etc / managed.relative_to(session / "etc"), readonly=True)
    for name in ("tmp", "run", "dev/shm"):
        (root / name).mkdir(parents=True, exist_ok=True)
    _mount("tmpfs", root / "tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=1g")
    _mount("tmpfs", root / "run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0755,size=4m")
    dev = root / "dev"
    _mount("tmpfs", dev, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755,size=1m")
    for name in DEVICES:
        if Path("/dev", name).exists():
            _bind(Path("/dev", name), dev / name, readonly=False, device=True)
    # A private devpts instance: the session's ptys cannot reach host terminals.
    (dev / "pts").mkdir()
    _mount("devpts", dev / "pts", "devpts", MS_NOSUID | MS_NOEXEC,
           "newinstance,ptmxmode=0666,mode=0620")
    (dev / "ptmx").symlink_to("pts/ptmx")
    (dev / "shm").mkdir(exist_ok=True)
    _mount("tmpfs", dev / "shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=256m")
    for link, target in (("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"),
                         ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")):
        (dev / link).symlink_to(target)
    for extra in plan["readonly_roots"]:
        _bind(Path(extra), root / extra.lstrip("/"), readonly=True)
    if plan["ca_bundle"]:
        _bind(Path(plan["ca_bundle"]), root / "run/bull/ca-bundle.crt", readonly=True)
    authority = Path(plan["authority_socket"]).parent
    _bind(authority, root / str(authority).lstrip("/"), readonly=True)
    _bind(session / "relay", root / "run/bull/relay", readonly=True)
    _bind(session / "workspace", root / WORKSPACE.lstrip("/"), readonly=False)
    _bind(session / "home", root / AGENT_HOME.lstrip("/"), readonly=False)
    (root / "proc").mkdir(exist_ok=True)
    _mount("proc", root / "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    return root


def _pivot(root: Path) -> None:
    old = root / ".old"
    old.mkdir()
    number = _PIVOT_ROOT.get(platform.machine())
    if number is None:
        raise LaunchBlocked(f"pivot_root is not mapped for {platform.machine()}")
    if _libc.syscall(number, str(root).encode(), str(old).encode()) != 0:
        raise OSError(ctypes.get_errno(), "pivot_root failed")
    os.chdir("/")
    if _libc.umount2(b"/.old", MNT_DETACH) != 0:
        raise OSError(ctypes.get_errno(), "detaching the host root failed")
    os.rmdir("/.old")
    # The root tmpfs itself becomes read-only: no new top-level paths.
    _mount(None, "/", flags=MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)


def _session_env(plan: dict) -> dict[str, str]:
    profile = PROFILES[plan["client"]]
    proxy = f"http://127.0.0.1:{RELAY_PORT}"
    paths = [str(Path(plan["client_binary"]).parent), "/usr/local/bin", "/usr/bin", "/bin"]
    for root in plan["readonly_roots"]:
        if Path(root, "bin").is_dir():
            paths.append(str(Path(root, "bin")))
    env = {
        "HOME": AGENT_HOME,
        "USER": plan["agent_user"],
        "LOGNAME": plan["agent_user"],
        "SHELL": "/bin/bash",
        "PATH": ":".join(dict.fromkeys(paths)),
        "TMPDIR": "/tmp",
        "HTTPS_PROXY": proxy,
        "https_proxy": proxy,
        "HTTP_PROXY": proxy,
        "http_proxy": proxy,
        "ALL_PROXY": proxy,
        "NO_PROXY": "",
        "no_proxy": "",
        **profile.env,
    }
    for name in ("TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "COLUMNS", "LINES"):
        if name in os.environ:
            env[name] = os.environ[name]
    if plan["ca_bundle"]:
        bundle = "/run/bull/ca-bundle.crt"
        env.update(SSL_CERT_FILE=bundle, NODE_EXTRA_CA_CERTS=bundle,
                   REQUESTS_CA_BUNDLE=bundle, CODEX_CA_CERTIFICATE=bundle)
    return env


def stage2(session: Path) -> int:
    """PID 1 of the session: build the root, then run the client as the agent."""
    plan = json.loads((session / "plan.json").read_text())
    api_key = None
    if plan["api_key_file"]:
        api_key = Path(plan["api_key_file"]).read_text().strip()
    _mount(None, "/", flags=MS_REC | MS_PRIVATE)
    root = _build_root(session, plan)
    _pivot(root)
    _loopback_up()
    env = _session_env(plan)
    if api_key:
        env[PROFILES[plan["client"]].api_key_env] = api_key
    uid, gid = plan["agent_uid"], plan["agent_gid"]
    from .inference_relay import forward_loopback
    from .seccomp_policy import install_agent_seccomp

    forwarder = os.fork()
    if forwarder == 0:
        try:
            _become_agent(uid, gid)
            install_agent_seccomp()
            forward_loopback(RELAY_PORT, "/run/bull/relay/relay.sock")
        except BaseException:
            traceback.print_exc()
        finally:
            os._exit(1)
    child = os.fork()
    if child == 0:
        try:
            os.chdir(WORKSPACE)
            _limits()
            _become_agent(uid, gid)
            install_agent_seccomp()
            argv = [plan["client_binary"], *plan["client_args"]]
            os.execve(argv[0], argv, env)
        except BaseException as exc:
            print(f"BULL managed session: client start failed: {exc}", file=sys.stderr)
            os._exit(126)
    # PID 1 reaps orphans until the client exits; its exit tears down the
    # PID namespace, which kills every remaining process in the session.
    status = 1
    while True:
        try:
            pid, code = os.wait()
        except ChildProcessError:
            break
        if pid == child:
            status = os.waitstatus_to_exitcode(code)
            break
    try:
        os.kill(forwarder, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return status if status >= 0 else 128 - status


# --------------------------------------------------------------- stage 1 (host)


def _start_relay(session: Path, plan: dict) -> int:
    from .inference_relay import InferenceRelay, parse_proxy_url

    path = session / "relay" / "relay.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # Session paths can exceed the 108-byte AF_UNIX limit; bind relatively.
    previous = os.getcwd()
    os.chdir(path.parent)
    try:
        listener.bind(path.name)
    finally:
        os.chdir(previous)
    os.chown(path, plan["agent_uid"], plan["agent_gid"])
    os.chmod(path, 0o600)
    listener.listen(64)
    log_fd = os.open(session / "relay.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    upstream = parse_proxy_url(plan["upstream_proxy"])
    pid = os.fork()
    if pid == 0:
        try:
            nobody = pwd.getpwnam("nobody")
            _become_agent(nobody.pw_uid, nobody.pw_gid)
            InferenceRelay(listener, plan["provider_hosts"], log_fd,
                           upstream_proxy=upstream).serve_forever()
        except BaseException:
            traceback.print_exc()
        finally:
            os._exit(0)
    listener.close()
    os.close(log_fd)
    return pid


def _cgroup(plan: dict, session: Path) -> Path | None:
    if plan["resource_mode"] != "cgroup":
        return None
    group = Path(plan["cgroup_parent"]) / ("session-" + session.name)
    group.mkdir()
    (group / "pids.max").write_text("4096")
    (group / "memory.max").write_text(str(8 << 30))
    (group / "cpu.max").write_text("400000 100000")
    return group


def launch(plan: dict, sessions_root: Path) -> tuple[int, Path]:
    blocked = [c for c in preflight(plan) if c["status"] != "PASS"]
    if blocked:
        raise LaunchBlocked("; ".join(f"{c['check']}: {c['detail']}" for c in blocked))
    session = prepare_session(plan, sessions_root)
    group = _cgroup(plan, session)
    relay = _start_relay(session, plan)
    started = time.time()

    def enter_cgroup():
        if group is not None:
            (group / "cgroup.procs").write_text(str(os.getpid()))

    command = [
        "unshare", "--mount", "--net", "--pid", "--ipc", "--uts", "--cgroup",
        "--fork", "--kill-child", "--propagation", "private",
        sys.executable, "-I", "-B", "-m", "bulldog.agent_launcher",
        "--stage2", str(session),
    ]
    process = subprocess.Popen(command, preexec_fn=enter_cgroup)
    try:
        code = process.wait(timeout=plan["max_seconds"])
    except subprocess.TimeoutExpired:
        process.kill()
        code = process.wait()
    except KeyboardInterrupt:
        process.send_signal(signal.SIGINT)
        code = process.wait()
    finally:
        os.kill(relay, signal.SIGKILL)
        os.waitpid(relay, 0)
    report = {
        "format": SESSION_FORMAT,
        "session": session.name,
        "client": plan["client"],
        "exit_code": code,
        "seconds": round(time.time() - started, 1),
        "coverage": coverage(plan),
        "relay_log": "relay.jsonl",
        "export": f"bull agent export --session {session}",
    }
    (session / "report.json").write_text(json.dumps(report, indent=2))
    return code, session


def coverage(plan: dict) -> dict:
    return {
        "mode": "managed-session",
        "native_tools": "contained: they run inside the session boundary",
        "filesystem": "allowlisted read-only root; disposable workspace copy is the only project path",
        "network": "loopback only; model provider through the allowlisted inference relay",
        "provider_hosts": plan["provider_hosts"],
        "provider_channel": "a data path: the model can send what it reads to its provider",
        "identity": f"agent uid {plan['agent_uid']}, no supplementary groups, no capabilities, no_new_privs",
        "seccomp": "agent profile: kernel-control, namespace-creating clone and TIOCSTI refused",
        "resource_limits": plan["resource_mode"],
        "export": "reviewed patch; protected and host-executed paths refused by default",
        "client_configuration": "system-managed, read-only inside the session",
        "enterprise_release": "UNQUALIFIED",
    }


# ---------------------------------------------------------------------- export


def _protected(relative: str) -> bool:
    return any(fnmatch.fnmatch(relative, pattern) for pattern in PROTECTED)


def changes(session: Path) -> list[dict]:
    plan = json.loads((session / "plan.json").read_text())
    original = json.loads((session / "manifest.json").read_text())
    workspace = session / "workspace"
    result = []
    seen = set()
    for dirpath, dirnames, filenames in os.walk(workspace):
        rel_dir = os.path.relpath(dirpath, workspace)
        dirnames[:] = [d for d in dirnames if not (rel_dir == "." and d == ".git")]
        for name in (*filenames, *[d for d in dirnames if Path(dirpath, d).is_symlink()]):
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if _excluded(rel, plan["excludes"]):
                continue
            seen.add(rel)
            full = Path(dirpath) / name
            info = full.lstat()
            if not stat.S_ISREG(info.st_mode):
                result.append({"path": rel, "change": "refused", "reason": "not a regular file"})
                continue
            digest = _digest(full)
            if rel not in original:
                kind = "added"
            elif original[rel] != digest:
                kind = "modified"
            else:
                continue
            entry = {"path": rel, "change": kind, "sha256": digest, "size": info.st_size}
            if _protected(rel):
                entry["protected"] = True
            if info.st_size > MAX_EXPORT_FILE:
                entry.update(change="refused", reason="larger than the export limit")
            result.append(entry)
    for rel in sorted(set(original) - seen):
        if rel.startswith(".git/"):
            continue
        entry = {"path": rel, "change": "deleted"}
        if _protected(rel):
            entry["protected"] = True
        result.append(entry)
    return sorted(result, key=lambda e: e["path"])


def write_patch(session: Path, entries: list[dict]) -> Path:
    plan = json.loads((session / "plan.json").read_text())
    project, workspace = Path(plan["project"]), session / "workspace"
    lines: list[str] = []
    for entry in entries:
        if entry["change"] == "refused":
            continue
        rel = entry["path"]

        def text(base: Path) -> list[str] | None:
            path = base / rel
            if not path.is_file():
                return []
            try:
                return path.read_text(encoding="utf-8").splitlines(keepends=True)
            except UnicodeDecodeError:
                return None

        before = text(project) if entry["change"] != "added" else []
        after = text(workspace) if entry["change"] != "deleted" else []
        if before is None or after is None:
            lines.append(f"Binary file {rel} {entry['change']}\n")
            continue
        lines.extend(difflib.unified_diff(before, after, f"a/{rel}", f"b/{rel}"))
    patch = session / "export.patch"
    patch.write_text("".join(lines))
    return patch


def _safe_target(project: Path, relative: str) -> Path:
    if relative.startswith("/") or ".." in Path(relative).parts:
        raise ValueError(f"unsafe path {relative}")
    target = project / relative
    for parent in [target, *target.parents]:
        if parent == project:
            break
        if parent.is_symlink():
            raise ValueError(f"{relative} passes through a symlink in the project")
    return target


def apply_export(session: Path, *, allow_protected: bool = False) -> list[dict]:
    """Copy reviewed workspace changes into the real project.

    Refuses protected paths unless allowed, and refuses any file the project
    changed since the session began (the reviewed patch would be stale).
    """
    plan = json.loads((session / "plan.json").read_text())
    original = json.loads((session / "manifest.json").read_text())
    project, workspace = Path(plan["project"]), session / "workspace"
    entries = changes(session)
    problems = [e for e in entries if e["change"] == "refused"]
    if not allow_protected:
        problems += [e for e in entries if e.get("protected")]
    for entry in entries:
        target = _safe_target(project, entry["path"])
        now = _digest(target) if target.is_file() and not target.is_symlink() else None
        if now != original.get(entry["path"]):
            problems.append({**entry, "reason": "project changed since the session began"})
    if problems:
        raise ValueError("export refused: " + json.dumps(problems))
    for entry in entries:
        target = _safe_target(project, entry["path"])
        if entry["change"] == "deleted":
            target.unlink()
            continue
        source = workspace / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.bull-{secrets.token_hex(4)}")
        shutil.copyfile(source, temporary)
        os.chmod(temporary, 0o755 if source.stat().st_mode & 0o111 else 0o644)
        os.replace(temporary, target)
    return entries


# ------------------------------------------------------------------------- CLI


def add_parser(commands):
    agent = commands.add_parser(
        "agent", help="Managed agent sessions: contain Codex or Claude Code entirely"
    )
    sub = agent.add_subparsers(dest="agent_command", required=True)
    for name, help_text in (("launch", "Start a contained session (sudo)"),
                            ("preflight", "Check every required control without launching")):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--client", choices=sorted(PROFILES), required=True)
        cmd.add_argument("--agent-user", required=True)
        cmd.add_argument("--project", type=Path, required=True)
        cmd.add_argument("--authority-socket", type=Path, required=True)
        cmd.add_argument("--authority-uid", type=int, required=True)
        cmd.add_argument("--sessions", type=Path, default=Path("/var/lib/bull-sessions"))
        cmd.add_argument("--client-binary")
        cmd.add_argument("--bull-mcp")
        cmd.add_argument("--provider-host", action="append", default=[])
        cmd.add_argument("--upstream-proxy")
        cmd.add_argument("--ca-bundle", type=Path)
        cmd.add_argument("--resource-mode", choices=("cgroup", "rlimit-only"), default="cgroup")
        cmd.add_argument("--cgroup-parent", type=Path)
        cmd.add_argument("--copy-credentials", action="store_true",
                         help="copy the agent account's own provider login into the session")
        cmd.add_argument("--api-key-file", type=Path)
        cmd.add_argument("--exclude", action="append", default=[])
        cmd.add_argument("--no-default-excludes", action="store_true")
        cmd.add_argument("--extra-ro", action="append", default=[])
        cmd.add_argument("--max-seconds", type=int)
        cmd.add_argument("client_args", nargs=argparse.REMAINDER)
        cmd.set_defaults(handler=_run_launch if name == "launch" else _run_preflight)
    export = sub.add_parser("export", help="Review or apply a session's workspace changes")
    export.add_argument("--session", type=Path, required=True)
    export.add_argument("--apply", action="store_true")
    export.add_argument("--allow-protected", action="store_true")
    export.set_defaults(handler=_run_export)


def _plan_from(args) -> dict:
    if args.client_args[:1] == ["--"]:
        args.client_args = args.client_args[1:]
    return build_plan(args)


def _run_preflight(args) -> int:
    try:
        checks = preflight(_plan_from(args))
    except (LaunchBlocked, KeyError, OSError) as exc:
        print(json.dumps({"status": "BLOCKED", "detail": str(exc)}))
        return 1
    ready = all(c["status"] == "PASS" for c in checks)
    print(json.dumps({"status": "READY" if ready else "BLOCKED", "checks": checks}, indent=2))
    return 0 if ready else 1


def _run_launch(args) -> int:
    try:
        code, session = launch(_plan_from(args), args.sessions)
    except (LaunchBlocked, KeyError, OSError) as exc:
        print(json.dumps({"status": "BLOCKED", "detail": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps({"status": "SESSION_ENDED", "exit_code": code, "session": str(session),
                      "next": f"bull agent export --session {session}"}), file=sys.stderr)
    return code


def _run_export(args) -> int:
    entries = changes(args.session)
    patch = write_patch(args.session, entries)
    if not args.apply:
        print(json.dumps({"changes": entries, "patch": str(patch)}, indent=2))
        return 0
    try:
        applied = apply_export(args.session, allow_protected=args.allow_protected)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"applied": applied}, indent=2))
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "--stage2":
        return stage2(Path(argv[1]))
    print("use `bull agent ...`", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
