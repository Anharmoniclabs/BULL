"""Race-free AF_UNIX socket binding and peer authentication.

Replaces the bind()-then-chmod() TOCTOU pattern found in secret_broker.py
and egress_proxy.py. bind() creates the socket node with permissions derived
from the process umask; chmod() afterwards leaves a window where any local
user can connect(). This module clamps the umask *around* bind(), verifies
the resulting node, and adds SO_PEERCRED peer authentication so a leaked or
raced socket path cannot be used by another local principal.

Doctrine: directory privacy + umask clamp + peer-credential check. Any one
layer alone has a failure mode; together they cover race, leak, and mount
exposure.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from pathlib import Path


class HardeningError(RuntimeError):
    """Raised when a hardening invariant cannot be established or is violated."""


def bind_private_unix_socket(
    path: str | Path,
    *,
    backlog: int = 16,
    timeout: float | None = 0.25,
) -> socket.socket:
    """Bind an AF_UNIX stream socket with no cross-user race window.

    - Parent directory is forced to mode 0o700 (owner-only traversal).
    - umask is clamped to 0o177 *during* bind(), so the node is born 0o600;
      there is no bind-then-chmod window.
    - Refuses to bind over any existing node (including symlinks), killing
      symlink-preplant attacks.
    - Post-bind lstat verifies the mode; any surprise tears down and raises.
    """
    path = Path(path)
    if not hasattr(socket, "AF_UNIX"):
        raise HardeningError("AF_UNIX sockets are not available on this platform")

    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o700)

    if path.is_symlink() or path.exists():
        raise HardeningError(f"refusing to bind over existing node: {path}")

    old_umask = os.umask(0o177)
    try:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
    except BaseException:
        try:
            server.close()  # noqa: B017 - defensive teardown
        except Exception:
            pass
        raise
    finally:
        os.umask(old_umask)

    st = os.lstat(path)
    if not stat.S_ISSOCK(st.st_mode):
        server.close()
        raise HardeningError(f"bound node is not a socket: {path}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        server.close()
        path.unlink(missing_ok=True)
        raise HardeningError(
            f"socket node has group/other permissions after clamped bind: {path}"
        )

    server.listen(backlog)
    server.settimeout(timeout)
    return server


def peer_credentials(conn: socket.socket) -> tuple[int, int, int]:
    """Return (pid, uid, gid) of the connected AF_UNIX peer via SO_PEERCRED."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise HardeningError("SO_PEERCRED is not available on this platform")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def require_peer_uid(conn: socket.socket, expected_uid: int | None = None) -> int:
    """Raise unless the peer is owned by expected_uid (default: current euid).

    Returns the verified peer uid. Call this on every accepted connection
    before serving any request.
    """
    if expected_uid is None:
        expected_uid = os.geteuid()
    _pid, uid, _gid = peer_credentials(conn)
    if uid != expected_uid:
        raise HardeningError(
            f"rejected peer uid {uid}; expected {expected_uid}"
        )
    return uid


def accept_authenticated(
    server: socket.socket,
    *,
    expected_uid: int | None = None,
) -> socket.socket:
    """accept() + peer-uid verification in one step. Rejected peers are closed."""
    conn, _addr = server.accept()
    try:
        require_peer_uid(conn, expected_uid)
    except BaseException:
        conn.close()
        raise
    return conn
