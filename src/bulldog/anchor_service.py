"""Durable authenticated audit checkpoints; serve behind a trusted TLS proxy."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat

MAX_FRAME = 65536


class AnchorError(ValueError):
    pass


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def session_key(master: bytes, session: str) -> bytes:
    if len(master) < 32 or not isinstance(session, str) or not re.fullmatch(r"[a-f0-9]{64}", session):
        raise AnchorError("invalid session or master key")
    return hmac.digest(master, b"bull-anchor-session-v1:" + session.encode(), "sha256")


def authenticate(payload: dict, key: bytes, *, purpose: str) -> dict:
    body = {k: v for k, v in payload.items() if k != "mac"}
    return dict(body, mac=hmac.new(key, purpose.encode() + b"\x00" + canonical(body), hashlib.sha256).hexdigest())


def verify(payload: dict, key: bytes, *, purpose: str) -> None:
    expected = authenticate(payload, key, purpose=purpose)["mac"]
    supplied = payload.get("mac")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise AnchorError("authentication failed")


def checkpoint(session: str, sequence: int, record: dict, key: bytes, *, include_record: bool = True) -> dict:
    payload = {"version": 1, "session": session, "sequence": sequence, "head_hash": record["record_hash"]}
    if include_record:
        payload["record"] = record
    else:
        payload["previous_hash"] = record["previous_hash"]
    return authenticate(payload, key, purpose="checkpoint")


def decode(raw: bytes) -> dict:
    if len(raw) > MAX_FRAME:
        raise AnchorError("frame exceeds size limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AnchorError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(AnchorError("nonfinite number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AnchorError("invalid JSON frame") from exc
    if not isinstance(value, dict):
        raise AnchorError("frame must be an object")
    return value


class AnchorStore:
    """One transaction per authenticated checkpoint, with exact-last retry."""

    def __init__(self, database: Path, master: bytes, *, max_bytes: int = 256 * 1024**2):
        if len(master) < 32:
            raise AnchorError("master key must contain at least 32 bytes")
        if database.is_symlink() or not database.parent.is_dir():
            raise AnchorError("database must have a real existing private parent")
        parent = database.parent.stat()
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise AnchorError("database parent must be owner-only")
        self.master = master
        self.database = database
        self.max_bytes = max_bytes
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS checkpoints (session TEXT NOT NULL, sequence INTEGER NOT NULL, head TEXT NOT NULL, frame BLOB NOT NULL, PRIMARY KEY(session, sequence))")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def accept(self, message: dict) -> dict:
        base = {"version", "session", "sequence", "head_hash", "mac"}
        if set(message) not in (base | {"record"}, base | {"previous_hash"}) or type(message["version"]) is not int or message["version"] != 1:
            raise AnchorError("invalid checkpoint fields")
        key = session_key(self.master, message["session"])
        frame = canonical(message)
        if len(frame) > MAX_FRAME:
            raise AnchorError("frame exceeds size limit")
        verify(message, key, purpose="checkpoint")
        seq, head, record = message["sequence"], message["head_hash"], message.get("record")
        if type(seq) is not int or not 1 <= seq <= 1_000_000:
            raise AnchorError("invalid sequence")
        if not isinstance(head, str) or not re.fullmatch(r"[a-f0-9]{64}", head):
            raise AnchorError("invalid record")
        if "record" in message:
            if not isinstance(record, dict):
                raise AnchorError("invalid record")
            body = {k: v for k, v in record.items() if k != "record_hash"}
            if record.get("record_hash") != head or hashlib.sha256(canonical(body)).hexdigest() != head:
                raise AnchorError("record hash mismatch")
            previous = record.get("previous_hash")
        else:
            previous = message["previous_hash"]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            last = db.execute("SELECT sequence, head, frame FROM checkpoints WHERE session=? ORDER BY sequence DESC LIMIT 1", (message["session"],)).fetchone()
            if last and seq == last[0] and frame == last[2]:
                pass  # Lost acknowledgement: exactly the latest committed frame only.
            else:
                if seq != (last[0] + 1 if last else 1) or previous != (last[1] if last else None):
                    raise AnchorError("checkpoint replay or conflicting history")
                pages = db.execute("PRAGMA page_count").fetchone()[0]
                page_size = db.execute("PRAGMA page_size").fetchone()[0]
                if pages * page_size + len(frame) + 16384 > self.max_bytes:
                    raise AnchorError("audit storage budget exhausted")
                db.execute("INSERT INTO checkpoints VALUES (?, ?, ?, ?)", (message["session"], seq, head, frame))
        # SQLite transaction has durably committed before an acknowledgement exists.
        return authenticate({"version": 1, "session": message["session"], "sequence": seq,
                             "head_hash": head, "accepted": True}, key, purpose="acknowledgement")


def make_server(store: AnchorStore, address: tuple[str, int]) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            pass  # No keys, records or request data in the default HTTP log.

        def do_POST(self):
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if self.path != "/v1/checkpoints" or len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                    raise AnchorError("invalid HTTP framing")
                length = int(lengths[0])
                if not 0 < length <= MAX_FRAME:
                    raise AnchorError("invalid content length")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise AnchorError("truncated request")
                result = store.accept(decode(raw))
                encoded, status = canonical(result), 200
            except (ValueError, TypeError, KeyError, OSError, sqlite3.Error):
                encoded, status = b'{"error":"checkpoint rejected"}', 409
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
            self.close_connection = True
    return HTTPServer(address, Handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--key-file", required=True, type=Path)
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--test-cert", type=Path)
    parser.add_argument("--test-tls-key", type=Path)
    args = parser.parse_args(argv)
    key_info = args.key_file.lstat()
    if not stat.S_ISREG(key_info.st_mode) or key_info.st_uid != os.getuid() or key_info.st_mode & 0o077 or not 32 <= key_info.st_size <= 4096:
        parser.error("key file must be an owner-only regular file")
    if bool(args.test_cert) != bool(args.test_tls_key):
        parser.error("both test TLS files are required")
    os.umask(0o077)
    store = AnchorStore(args.database, args.key_file.read_bytes())
    server = make_server(store, ("127.0.0.1", args.port))
    if args.test_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.test_cert, args.test_tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
