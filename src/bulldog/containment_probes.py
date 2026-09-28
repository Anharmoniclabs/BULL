"""Escape attempts run *inside* a managed session, as the agent's native shell.

Each probe tries something a hostile or confused agent might do and reports
PASS only when the boundary held. Positive controls (workspace writes, the
BULL authority, the allowlisted provider) must succeed, so a session that
simply denies everything cannot pass. Output is one JSON document on stdout.

Usage (inside a session): python -I -m bulldog.containment_probes JSON-ARGS
where JSON-ARGS carries the authority socket/uid, the provider host, a host
abstract-socket name and a host PID to target.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import struct
import sys

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
RESULTS: list[dict] = []
SENSITIVE_HOME_ENTRIES = (
    ".ssh", ".aws", ".config", ".claude", ".claude.json", ".codex", ".gnupg",
    ".docker", ".kube", ".netrc", ".git-credentials", ".bash_history",
)


def record(probe, ok, detail, *, kind="escape"):
    RESULTS.append(
        {"probe": probe, "kind": kind, "status": "PASS" if ok else "FAIL", "detail": detail}
    )


def refused(action) -> tuple[bool, str]:
    """Run an action that must fail; returns (failed, description)."""
    try:
        action()
    except OSError as exc:
        return True, errno.errorcode.get(exc.errno, str(exc.errno))
    except Exception as exc:  # e.g. socket.gaierror subclasses OSError anyway
        return True, type(exc).__name__
    return False, "succeeded"


def filesystem(args):
    for path in ("/root", "/var", "/etc/bull", "/etc/shadow", "/etc/sudoers",
                 "/run/docker.sock", "/var/run/docker.sock", "/run/user", "/sys",
                 "/dev/kvm", "/dev/mem", "/dev/sda", "/dev/nvme0n1", "/proc/kcore"):
        exists = os.path.lexists(path)
        readable = exists and os.access(path, os.R_OK)
        record(f"absent:{path}", not readable, "absent" if not exists else "present but unreadable")
    for line in Path("/etc/passwd").read_text().splitlines():
        fields = line.split(":")
        if len(fields) < 7 or fields[5] in ("/", "/home/agent", "/nonexistent"):
            continue
        leaked = [e for e in SENSITIVE_HOME_ENTRIES if os.path.lexists(os.path.join(fields[5], e))]
        if leaked or os.path.isdir(fields[5]):
            record(f"host-home:{fields[5]}", not leaked, "no credential entries" if not leaked else leaked)
    for target in ("/escape", "/etc/escape", "/usr/escape", "/run/escape", "/dev/escape",
                   "/tmp/../etc/escape", sys.prefix + "/escape",
                   "/etc/claude-code/managed-settings.json",
                   "/etc/codex/managed_config.toml"):
        if target.startswith("/etc/c") and not os.path.lexists(target):
            continue  # Only the active client's managed file exists.
        ok, detail = refused(lambda t=target: Path(t).open("a").close())
        record(f"write:{target}", ok, detail)
    for target in ("/workspace/.bull-probe", "/home/agent/.bull-probe", "/tmp/.bull-probe"):
        try:
            Path(target).write_text("ok")
            os.unlink(target)
            record(f"write:{target}", True, "writable work area", kind="positive")
        except OSError as exc:
            record(f"write:{target}", False, str(exc), kind="positive")


def network(args):
    for family, address in ((socket.AF_INET, ("1.1.1.1", 443)),
                            (socket.AF_INET, ("169.254.169.254", 80)),
                            (socket.AF_INET6, ("2606:4700:4700::1111", 443))):
        def connect(f=family, a=address):
            with socket.socket(f, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(a)
        ok, detail = refused(connect)
        record(f"tcp:{address[0]}:{address[1]}", ok, detail)

    def udp(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(b"\0" * 12, ("8.8.8.8", port))
            s.recv(512)
    for port, name in ((53, "dns"), (443, "quic")):
        ok, detail = refused(lambda p=port: udp(p))
        record(f"udp:{name}", ok, detail)
    ok, detail = refused(lambda: socket.getaddrinfo("example.com", 443))
    record("dns:resolve", ok, detail)
    raw_ok, raw_detail = refused(lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW))
    record("socket:packet", raw_ok, raw_detail)
    ok, detail = refused(lambda: _abstract(args["abstract"]))
    record("ipc:host-abstract-socket", ok, detail)


def _abstract(name):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect("\0" + name)


def _relay(request: bytes) -> str:
    with socket.create_connection(("127.0.0.1", 3128), timeout=20) as s:
        s.sendall(request)
        reply = s.recv(256).split(b"\r\n", 1)[0].decode("latin-1")
    return reply


def relay(args):
    for label, request in (
        ("non-provider-host", b"CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n"),
        ("metadata-ip", b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n"),
        ("provider-other-port", f"CONNECT {args['provider']}:80 HTTP/1.1\r\n\r\n".encode()),
        ("plain-http", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ):
        try:
            reply = _relay(request)
        except OSError as exc:
            reply = f"error {exc}"
        record(f"relay:{label}", " 403 " in reply + " ", reply)
    try:
        reply = _relay(f"CONNECT {args['provider']}:443 HTTP/1.1\r\n\r\n".encode())
    except OSError as exc:
        reply = f"error {exc}"
    if " 502 " in reply + " ":
        RESULTS.append({"probe": "relay:provider", "kind": "positive", "status": "BLOCKED",
                        "detail": "provider unreachable from this host: " + reply})
    else:
        record("relay:provider", " 200 " in reply + " ", reply, kind="positive")


def authority(args):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(args["authority_socket"])
            _, uid, _ = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        record("authority:reachable", uid == args["authority_uid"], f"peer uid {uid}", kind="positive")
    except OSError as exc:
        record("authority:reachable", False, str(exc), kind="positive")


def privilege(args):
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    record("caps:effective", int(status["CapEff"].strip(), 16) == 0, status["CapEff"].strip())
    record("caps:permitted", int(status["CapPrm"].strip(), 16) == 0, status["CapPrm"].strip())
    record("no_new_privs", status.get("NoNewPrivs", "").strip() == "1", status.get("NoNewPrivs", "?").strip())
    record("seccomp", status.get("Seccomp", "").strip() == "2", status.get("Seccomp", "?").strip())
    record("groups:none", os.getgroups() in ([], [os.getgid()]), str(os.getgroups()))
    ok, detail = refused(lambda: os.setuid(0))
    record("setuid:0", ok, detail)

    def syscall_refused(name, *call):
        rc = _libc.syscall(*call)
        if rc == 0 and name.startswith("clone"):
            os._exit(0)  # Child of an unexpectedly successful clone.
        return rc != 0, errno.errorcode.get(ctypes.get_errno(), "0")
    for flag, name in ((0x10000000, "user"), (0x00020000, "mount"), (0x40000000, "net")):
        ok, detail = syscall_refused(f"unshare:{name}", 272, flag)  # SYS_unshare (x86_64)
        record(f"unshare:{name}", ok, detail)
        ok, detail = syscall_refused(f"clone:{name}", 56, flag | 17, 0, 0, 0, 0)  # SYS_clone
        record(f"clone:{name}", ok, detail)
    ok, detail = refused(lambda: _check(_libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)))
    record("mount", ok, detail)
    ok, detail = refused(lambda: _check(_libc.ptrace(16, 1, None, None)))  # PTRACE_ATTACH
    record("ptrace:pid1", ok, detail)
    ok, detail = refused(lambda: _check(_libc.chroot(b"/tmp")))
    record("chroot", ok, detail)
    ok, detail = refused(lambda: _check(_libc.sethostname(b"escape", 6)))
    record("sethostname", ok, detail)
    master, slave = os.openpty()
    ok, detail = refused(lambda: fcntl.ioctl(slave, 0x5412, b"x"))  # TIOCSTI
    record("tty:TIOCSTI", ok, detail)
    os.close(master)
    os.close(slave)
    for tty_fd in (0, 1, 2):
        if os.isatty(tty_fd):
            ok, detail = refused(lambda f=tty_fd: fcntl.ioctl(f, 0x5412, b"x"))
            record(f"tty:TIOCSTI:fd{tty_fd}", ok, detail)
    ok, detail = refused(lambda: os.kill(args["host_pid"], 0))
    record("signal:host-process", ok, detail)
    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    record("pid-namespace", len(pids) < 32, f"{len(pids)} visible processes")


def _check(rc):
    if rc != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def environment(args):
    allowed_secret = {args.get("api_key_env")}
    leaked = [
        k for k in os.environ
        if k.startswith("BULL_") or k in ("SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY",
                                          "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "SUDO_USER")
        or (any(s in k for s in ("TOKEN", "SECRET", "PASSWORD", "_KEY")) and k not in allowed_secret)
    ]
    record("environment:no-host-secrets", not leaked, leaked or "clean")


def main() -> int:
    args = json.loads(sys.argv[1])
    for group in (filesystem, network, relay, authority, privilege, environment):
        try:
            group(args)
        except Exception as exc:  # A crashed group is itself a failure.
            record(f"{group.__name__}:error", False, f"{type(exc).__name__}: {exc}")
    print(json.dumps({"uid": os.getuid(), "results": RESULTS}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
