from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .verify import main as verify_main


def _run_verify(args: argparse.Namespace) -> int:
    forwarded = ["bull verify"]

    if args.audit is not None:
        forwarded.extend([
            "--audit",
            str(args.audit),
        ])

    if args.json is not None:
        forwarded.extend([
            "--json",
            str(args.json),
        ])

    original_argv = sys.argv

    try:
        sys.argv = forwarded
        return verify_main()
    finally:
        sys.argv = original_argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bull",
        description="BULL AI execution-governance runtime",
    )

    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify BULL runtime and optional audit ledger.",
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

    verify_parser.set_defaults(handler=_run_verify)
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
