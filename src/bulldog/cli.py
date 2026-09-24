from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .models import Capability
from .profiles import DEVELOPMENT_WARNING
from .verify import main as verify_main


def _run_verify(args: argparse.Namespace) -> int:
    if not args.production:
        print("=" * 78, file=sys.stderr)
        print(DEVELOPMENT_WARNING, file=sys.stderr)
        print("=" * 78, file=sys.stderr)

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


def _run_policy(args: argparse.Namespace) -> int:
    from .policy_bundle import sign_policy_bundle

    key = os.environ.get(args.key_env)
    if not key:
        print(
            f"missing policy signing key in environment variable {args.key_env}",
            file=sys.stderr,
        )
        return 2

    capabilities = args.capability or [cap.value for cap in Capability]
    try:
        signed = sign_policy_bundle(
            project_root=args.project_root,
            allowed_capabilities=capabilities,
            key=key,
            key_id=args.key_id,
            human_approval=(json.loads(args.approval_config.read_text()) if args.approval_config else None),
        )
    except Exception as exc:
        print(f"unable to create policy bundle: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(signed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output)
    return 0



def _run_assurance_status(args: argparse.Namespace) -> int:
    from .assurance import evaluate_assurance

    try:
        report = evaluate_assurance(
            dynamic=args.dynamic,
            release_dir=args.release_dir,
        )
    except Exception as exc:
        print(f"unable to evaluate assurance profile: {exc}", file=sys.stderr)
        return 2

    payload = report.to_dict()
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(f"{report.profile_id}  digest={report.profile_digest}")
    for phase in ("source", "deployment", "release", "external"):
        phase_controls = [item for item in report.controls if item.phase == phase]
        if not phase_controls:
            continue
        print(f"\n{phase.upper()}")
        for item in phase_controls:
            suffix = f" — {item.detail}" if item.detail else ""
            print(f"  {item.status:<11} {item.control_id}{suffix}")
    print("\nSUMMARY")
    print("  source_complete:", str(report.source_complete).lower())
    print("  deployment_complete:", str(report.deployment_complete).lower())
    if report.release_complete is not None:
        print("  release_complete:", str(report.release_complete).lower())
    print("  certified: false")

    complete = report.source_complete and report.deployment_complete
    if report.release_complete is not None:
        complete = complete and report.release_complete
    return 1 if args.require_complete and not complete else 0


def _run_console(args: argparse.Namespace) -> int:
    from .control_plane import serve_console

    return serve_console(
        host=args.host,
        port=args.port,
        workspace=args.workspace,
        refresh_seconds=args.refresh_seconds,
        auto_scan=not args.no_auto_scan,
        dynamic_attestation=not args.no_dynamic_attestation,
    )

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

    console_parser = subparsers.add_parser(
        "console",
        help="Run the local BULL command/control operator console.",
    )
    console_parser.add_argument("--host", default="127.0.0.1")
    console_parser.add_argument("--port", type=int, default=11510)
    console_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    console_parser.add_argument("--refresh-seconds", type=float, default=2.0)
    console_parser.add_argument(
        "--no-auto-scan",
        action="store_true",
        help="Initialize ClamAV but do not start the bounded workspace scan on boot.",
    )
    console_parser.add_argument(
        "--no-dynamic-attestation",
        action="store_true",
        help="Do not start the live assurance probe on boot.",
    )
    console_parser.set_defaults(handler=_run_console)

    assurance_parser = subparsers.add_parser(
        "assurance",
        help="Inspect BULL machine-readable assurance evidence.",
    )
    assurance_subparsers = assurance_parser.add_subparsers(dest="assurance_command")
    assurance_status = assurance_subparsers.add_parser(
        "status",
        help="Report source, deployment, release, and external control status.",
    )
    assurance_status.add_argument(
        "--dynamic",
        action="store_true",
        help="Launch the real namespace backend and require live security attestation.",
    )
    assurance_status.add_argument(
        "--release-dir",
        type=Path,
        help="Optional release directory containing SBOM and attestation evidence.",
    )
    assurance_status.add_argument(
        "--json",
        type=Path,
        help="Optional path for a machine-readable assurance report.",
    )
    assurance_status.add_argument(
        "--require-complete",
        action="store_true",
        help="Return non-zero unless all in-scope required controls pass.",
    )
    assurance_status.set_defaults(handler=_run_assurance_status)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Generate a signed integrity manifest for the installed BULL TCB.",
    )
    manifest_parser.add_argument("--output", type=Path, required=True)
    manifest_parser.add_argument(
        "--key-env",
        default="BULL_INTEGRITY_MANIFEST_KEY",
    )
    manifest_parser.add_argument("--key-id", default="deployment")
    manifest_parser.set_defaults(handler=_run_manifest)

    policy_parser = subparsers.add_parser(
        "policy",
        help="Generate a signed production capability policy bundle.",
    )
    policy_parser.add_argument("--output", type=Path, required=True)
    policy_parser.add_argument("--approval-config", type=Path, help="Host-owned JSON approval configuration to include in signed policy.")
    policy_parser.add_argument("--project-root", default="/workspace")
    policy_parser.add_argument(
        "--capability",
        action="append",
        choices=[cap.value for cap in Capability],
        help="Allowed production capability; repeat as needed. Defaults to all.",
    )
    policy_parser.add_argument(
        "--key-env",
        default="BULL_POLICY_BUNDLE_KEY",
    )
    policy_parser.add_argument("--key-id", default="deployment-policy")
    policy_parser.set_defaults(handler=_run_policy)
    from .approval_cli import add_parser as add_approval_parser
    from .hardware_approval.cli import add_parser as add_hardware_parser
    add_hardware_parser(subparsers)
    add_approval_parser(subparsers)
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
