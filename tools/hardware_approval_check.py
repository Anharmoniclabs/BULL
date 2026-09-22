#!/usr/bin/env python3
"""Interactive harmless approval ceremony on an operator's enrolled device.

This is a hardware-protocol check, not a production host/KVM certification.
It never publishes, deletes, sends, or retrieves real secrets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from bulldog.approval import ApprovalGate, ApprovalProof, ApprovalError, canonical_bytes
from bulldog.audit import AuditLedger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    config = {"state_directory": str(root), "credentials": {"operator": " ".join(args.public_key.read_text().split()[:2])},
              "ttl_seconds": 300, "routine_egress_urls": []}
    ledger = AuditLedger(root / "audit.jsonl")
    gate = ApprovalGate(config, audit=ledger.append_event, policy_digest="hardware-ceremony-v1")
    binding = {"operation": "publish", "target": "local harmless fixture only", "policy_digest": gate.policy_digest,
               "content_sha256": hashlib.sha256(b"BULL approval fixture").hexdigest(), "session_id": os.urandom(32).hex()}
    request = gate.request(binding)
    message = root / "request.json"
    message.write_bytes(canonical_bytes(request))
    result = subprocess.run([sys.executable, "-m", "bulldog.cli", "approval", "sign", "--request", str(message),
                             "--key", str(args.key.resolve()), "--output", str(root / "proof.sig")], check=False)
    if result.returncode:
        return result.returncode
    proof = ApprovalProof(request["request_id"], "operator", (root / "proof.sig").read_bytes())
    gate.consume(binding, proof)
    gate.finish(proof.request_id, "completed")
    rejected = False
    try:
        gate.consume(binding, proof)
    except ApprovalError:
        rejected = True
    report = {"format": "bull-hardware-ceremony-v1", "credential_protocol_verified": True,
              "signed_presence_and_verification": True, "replay_rejected": rejected,
              "audit_valid": ledger.verify().valid, "hardware_enrollment": "operator-managed, not remotely attested",
              "trusted_action_display": "not established", "production_certified": False}
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if rejected and report["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
