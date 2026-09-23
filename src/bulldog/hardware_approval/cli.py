"""Operator diagnostics and disabled public enrollment records; no software YES."""
import json
from pathlib import Path

from ..approval_crypto import ApprovalError
from .provider import KIND, validate_credential


def run(args):
    try:
        if args.hardware_command in {"status", "test-buttons"}:
            from .diagnostic import main
            argv = ["--serial", args.serial] if args.serial else []
            if args.hardware_command == "test-buttons":
                argv.append("--test-clicks")
            main(argv)
        else:
            from ..approval_cli import _write_new
            record = {"type": KIND, "protocol": "BULL-AUTH-1", "device_id": args.device_id,
                      "public_key": args.public_key, "enabled": False,
                      "provisioning": {"part": args.part, "serial": args.serial,
                                       "config_sha256": args.config_sha256,
                                       "firmware_sha256": args.firmware_sha256,
                                       "key_origin": "secure-element-generated"}}
            validate_credential(record)
            _write_new(args.output, (json.dumps(record, indent=2) + "\n").encode())
            print("Disabled enrollment record saved. It grants no authority; verify hardware before signing it into policy.")
        return 0
    except (ApprovalError, OSError, ValueError) as exc:
        print("Hardware operation stopped: " + str(exc))
        return 2


def add_parser(subparsers):
    parser = subparsers.add_parser("hardware", help="Inspect prototype hardware; no host approval control.")
    commands = parser.add_subparsers(dest="hardware_command", required=True)
    for name in ("status", "test-buttons"):
        command = commands.add_parser(name)
        command.add_argument("--serial")
        command.set_defaults(handler=run)
    enrollment = commands.add_parser("enrollment-record", help="Record inspected public material, disabled by default.")
    for name in ("device-id", "public-key", "part", "serial", "config-sha256", "firmware-sha256"):
        enrollment.add_argument("--" + name, required=True)
    enrollment.add_argument("--output", type=Path, required=True)
    enrollment.set_defaults(handler=run)
