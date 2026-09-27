"""One bounded request per Unix connection; both sides verify kernel identity."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import threading

from .gateway_wire import (
    GatewayDenied,
    MAX_REQUEST,
    MAX_RESPONSE,
    encode_message,
    read_frame,
)
from .socket_hardening import (
    bind_private_unix_socket,
    peer_credentials,
    require_peer_uid,
)


def endpoint_path(path: Path, owner: int):
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise GatewayDenied("endpoint must have a canonical absolute parent")
    info = path.parent.stat()
    if info.st_uid != owner or info.st_mode & 0o022:
        raise GatewayDenied(
            "endpoint directory must be owned by the authority without group/other write"
        )
    for parent in path.parent.parents:
        info = parent.stat()
        # Sticky /tmp is safe when the authority-owned immediate directory is
        # neither replaceable nor traversed through a symlink.
        if info.st_uid not in {0, owner} or (
            info.st_mode & 0o022
            and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
        ):
            raise GatewayDenied("untrusted endpoint ancestor")


def request(socket_path: Path, *, server_uid: int, message: dict) -> dict:
    if type(server_uid) is not int or server_uid <= 0:
        raise GatewayDenied("non-root authority UID is required")
    endpoint_path(socket_path, server_uid)
    info = socket_path.lstat()
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != server_uid
        or info.st_mode & 0o007
    ):
        raise GatewayDenied("untrusted endpoint node")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(socket_path))
        require_peer_uid(conn, server_uid)
        conn.sendall(encode_message(message, limit=MAX_REQUEST))
        # One request, no reconnect or effect retry after a lost response.
        return read_frame(conn, limit=MAX_RESPONSE, timeout=150)


class GatewayServer:
    def __init__(self, authority, path: Path, *, agent_gid: int):
        endpoint_path(path, os.geteuid())
        info = path.parent.stat()
        if info.st_gid != agent_gid:
            raise GatewayDenied(
                "endpoint directory must have the selected agent access group"
            )
        self.authority = authority
        self.path = path
        self.stop_event = threading.Event()
        self.socket = bind_private_unix_socket(path, backlog=8, timeout=0.5)
        self.identity = path.lstat().st_ino
        try:
            os.chown(path, -1, agent_gid)
            os.chmod(path, 0o660)
            os.chmod(path.parent, 0o710)
        except BaseException:
            self.close()
            raise

    def close(self):
        self.stop_event.set()
        self.socket.close()
        try:
            if self.path.lstat().st_ino == self.identity:
                self.path.unlink()
        except FileNotFoundError:
            pass

    def serve(self):
        while not self.stop_event.is_set():
            try:
                conn, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    return
                raise
            with conn:
                try:
                    _, uid, _ = peer_credentials(conn)
                    if uid != self.authority.config["agent_uid"]:
                        continue  # Reject before reading or exposing the tool menu.
                    message = read_frame(conn, limit=MAX_REQUEST, timeout=3)
                    value = self.authority.handle(message, peer_uid=uid)
                    response = {"ok": True, "result": value}
                except GatewayDenied as exc:
                    response = {"ok": False, "error": str(exc)}
                except Exception:
                    response = {
                        "ok": False,
                        "error": "authority refused the request; inspect private operator audit",
                    }
                try:
                    conn.settimeout(3)
                    conn.sendall(encode_message(response))
                except (OSError, GatewayDenied):
                    pass
