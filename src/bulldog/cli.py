from __future__ import annotations

import argparse
import json
import os
import subprocess
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


def _run_up(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser().resolve()
    server = workspace / "ui" / "bull-command-center" / "dashboard_server.py"
    if not server.is_file():
        print(
            "BULL command center is not present in this workspace: " + str(server),
            file=sys.stderr,
        )
        return 2

    state = Path(
        os.environ.get(
            "BULL_COMMAND_CENTER_STATE",
            str(Path.home() / ".local" / "share" / "bull" / "command-center"),
        )
    ).expanduser()
    audit_dir = state / "audit"
    snapshot_dir = state / "snapshots"
    audit_dir.mkdir(parents=True, exist_ok=True)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("BULL_COMMAND_CENTER_STATE", str(state))
    os.environ.setdefault("BULL_AUDIT_LEDGER", str(audit_dir / "ledger.jsonl"))
    os.environ.setdefault("BULL_SNAPSHOT_ROOT", str(snapshot_dir))

    command = [
        sys.executable,
        str(server),
        "--port",
        str(args.port),
    ]
    if args.host:
        command.extend(["--host", args.host])
    if not args.no_open_browser:
        command.append("--open-browser")

    print("=" * 78)
    print("BULL COMMAND CENTER")
    print("=" * 78)
    print("workspace:", workspace)
    print("state:", state)
    print("audit:", os.environ["BULL_AUDIT_LEDGER"])
    print("snapshot scratch:", os.environ["BULL_SNAPSHOT_ROOT"])
    print("=" * 78)
    try:
        return subprocess.call(command, cwd=workspace, env=dict(os.environ))
    except KeyboardInterrupt:
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

    up_parser = subparsers.add_parser(
        "up",
        help="Start the BULL Command Center for this repository.",
    )
    up_parser.add_argument("--workspace", type=Path, default=Path.cwd())
    up_parser.add_argument(
        "--host",
        default=None,
        help="Bind host. Defaults to 0.0.0.0 in Codespaces and 127.0.0.1 locally.",
    )
    up_parser.add_argument("--port", type=int, default=8000)
    up_parser.add_argument(
        "--no-open-browser",
        action="store_true",
        help="Do not open a local browser automatically.",
    )
    up_parser.set_defaults(handler=_run_up)

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
