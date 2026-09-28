"""Run the BULL authority for OpenShell: middleware, interceptor, operator socket.

    python -m bulldog.openshell.server --bundle policy.json --key-file key \
        --ledger audit.jsonl --middleware 0.0.0.0:50061 \
        --interceptor unix:///run/bull/interceptor.sock --admin /run/bull/admin.sock

The admin socket is the operator's channel (list pending approvals, approve
one). It is a private Unix socket, never exposed to sandboxes.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import socket
import threading

from ..audit import AuditLedger
from ..policy_bundle import load_policy_bundle
from .authority import OpenShellAuthority
from .services import serve


def admin_loop(authority: OpenShellAuthority, path: Path) -> None:
    if path.exists():
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o077)
    try:
        listener.bind(str(path))
    finally:
        os.umask(old)
    listener.listen(8)
    while True:
        conn, _ = listener.accept()
        with conn:
            try:
                request = json.loads(conn.makefile("rb").readline())
                if request.get("cmd") == "pending":
                    reply = {"ok": True, "approvals": authority.approvals.listing()}
                elif request.get("cmd") == "approve":
                    entry = authority.approvals.approve(str(request["id"]))
                    authority._audit("openshell_approval", approval_id=request["id"],
                                     summary=entry["summary"])
                    reply = {"ok": True, "approved": request["id"]}
                else:
                    reply = {"ok": False, "error": "unknown command"}
            except (KeyError, ValueError) as exc:
                reply = {"ok": False, "error": str(exc)}
            conn.sendall((json.dumps(reply) + "\n").encode())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--middleware", required=True, help="host:port reachable by sandboxes")
    parser.add_argument("--interceptor", required=True, help="unix:///path or host:port")
    parser.add_argument("--admin", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True,
                        help="authority state file (provenance, approvals)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    bundle = load_policy_bundle(args.bundle, args.key_file.read_bytes().strip())
    if "openshell" not in bundle.raw:
        parser.error("signed bundle has no openshell grants section")
    authority = OpenShellAuthority(bundle.raw["openshell"], bundle.capability_ceiling,
                                   ledger=AuditLedger(args.ledger), state_path=args.state)
    servers = serve(authority, middleware_bind=args.middleware,
                    interceptor_bind=args.interceptor)
    threading.Thread(target=admin_loop, args=(authority, args.admin), daemon=True).start()
    print(json.dumps({"status": "LISTENING", "middleware": args.middleware,
                      "interceptor": args.interceptor}), flush=True)
    try:
        servers[0].wait_for_termination()
    except KeyboardInterrupt:
        pass
    for server in servers:
        server.stop(grace=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
