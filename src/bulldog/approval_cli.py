"""Operator CLI: export/cancel a pending request; signing is a separate ceremony.

This command never executes an agent action or enrolls credentials implicitly.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from .approval import ApprovalError, ApprovalGate, FORMAT, canonical_bytes, digest
from .approval_crypto import NAMESPACE, SSH_KEYGEN


def _host_gate():
    from .policy_bundle import load_policy_bundle
    from .audit import AuditLedger
    from .audit_transport import production_transport_from_environment
    bundle = load_policy_bundle(os.environ["BULL_POLICY_BUNDLE"], os.environ["BULL_POLICY_BUNDLE_KEY"])
    config = bundle.raw.get("human_approval")
    if config is None:
        raise ApprovalError("signed human approval configuration is missing")
    ledger = AuditLedger(os.environ["BULL_AUDIT_LEDGER"], transport=production_transport_from_environment())
    return ApprovalGate(config, audit=ledger.append_event, policy_digest=digest(canonical_bytes(bundle.raw)))


def _write_new(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def run(args) -> int:
    try:
        if args.approval_command == "show":
            state = _host_gate().inspect(args.request_id)
            print(json.dumps(state, indent=2, ensure_ascii=True))
            if args.output:
                if state["state"] != "pending":
                    raise ApprovalError("only pending requests can be exported")
                _write_new(args.output, canonical_bytes(state["request"]))
        elif args.approval_command == "cancel":
            _host_gate().cancel(args.request_id)
            print("Approval request cancelled; no action executed.")
        elif args.approval_command == "sign":
            # Freeze the bytes before display/signing to avoid a file-change race.
            raw = args.request.read_bytes()
            if len(raw) > 40000:
                raise ApprovalError("request exceeds size limit")
            request = json.loads(raw)
            if set(request) != {"format", "request_id", "issued_at", "expires_at", "action"} or request["format"] != FORMAT:
                raise ApprovalError("invalid approval request")
            if raw != canonical_bytes(request):
                raise ApprovalError("request is not in canonical BULL encoding")
            now = time.time()
            if not request["issued_at"] <= now < request["expires_at"]:
                raise ApprovalError("request is expired or future-dated")
            print(json.dumps(request, indent=2, ensure_ascii=True), flush=True)
            print("Verify the action above on this trusted operator machine. The authenticator must require presence and verification.", flush=True)
            with tempfile.TemporaryDirectory(prefix="bull-operator-") as directory:
                message = Path(directory) / "request.json"
                message.write_bytes(raw)
                result = subprocess.run(
                    [SSH_KEYGEN, "-Y", "sign", "-f", str(args.key.resolve(strict=True)),
                     "-n", NAMESPACE, str(message)],
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=120, check=False,
                )
                if result.returncode:
                    raise ApprovalError("authenticator signing did not complete")
                _write_new(args.output, message.with_suffix(".json.sig").read_bytes())
            print("Signature saved. No system action was executed.")
        return 0
    except (ApprovalError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print("Approval stopped: " + str(exc))
        return 2


def add_parser(subparsers):
    parser = subparsers.add_parser("approval", help="Inspect, cancel or physically sign a pending action.")
    commands = parser.add_subparsers(dest="approval_command", required=True)
    show = commands.add_parser("show")
    show.add_argument("request_id")
    show.add_argument("--output", type=Path)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("request_id")
    sign = commands.add_parser("sign")
    sign.add_argument("--request", type=Path, required=True)
    sign.add_argument("--key", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    for command in (show, cancel, sign):
        command.set_defaults(handler=run)
