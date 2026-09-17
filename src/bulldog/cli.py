from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .verify import main as verify_main


def _run_verify(args: argparse.Namespace) -> int:
    forwarded = ["bull verify"]
    if args.audit is not None:
        forwarded.extend(["--audit", str(args.audit)])
    if args.json is not None:
        forwarded.extend(["--json", str(args.json)])
    if args.production:
        forwarded.append("--production")

    original_argv = sys.argv
    try:
        sys.argv = forwarded
        return verify_main()
    finally:
        sys.argv = original_argv


def _run_manifest(args: argparse.Namespace) -> int:
    from .integrity import build_integrity_manifest, sign_integrity_manifest

    key = os.environ.get(args.key_env)
    if not key:
        print(
            f"missing integrity signing key in environment variable {args.key_env}",
            file=sys.stderr,
        )
        return 2

    package_root = Path(__file__).resolve().parent
    manifest = sign_integrity_manifest(
        build_integrity_manifest(package_root),
        key,
        key_id=args.key_id,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bull",
        description="BULL AI execution-governance runtime",
    )
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify BULL runtime and optional production boundary.",
    )
    verify_parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="Optional audit JSONL ledger to verify.",
    )
    verify_parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional JSON verification report path.",
    )
    verify_parser.add_argument(
        "--production",
        action="store_true",
        help="Require strict production security gates and live backend attestation.",
    )
    verify_parser.set_defaults(handler=_run_verify)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Generate a signed integrity manifest for the installed BULL TCB.",
    )
    manifest_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path for the signed JSON integrity manifest.",
    )
    manifest_parser.add_argument(
        "--key-env",
        default="BULL_INTEGRITY_MANIFEST_KEY",
        help="Environment variable holding the manifest HMAC key.",
    )
    manifest_parser.add_argument(
        "--key-id",
        default="deployment",
        help="Non-secret identifier recorded with the manifest signature.",
    )
    manifest_parser.set_defaults(handler=_run_manifest)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
