#!/usr/bin/env python3
"""Exercise an already provisioned local authority through real IPC and MCP.

Run as the enrolled agent account. --tool explicitly selects one fixed tool to
execute. This is connected-tool evidence, never whole-agent qualification.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from bulldog.gateway_transport import request
from bulldog.integrity import build_integrity_manifest


def validate_execution_result(data, expected_argv=None):
    """Judge the observed effect, not a successful protocol response."""
    if not isinstance(data, dict) or data.get("executed") is not True:
        raise ValueError(
            "selected tool did not execute; inspect private authority audit"
        )
    if expected_argv is not None and (
        data.get("status") != "COMPLETED"
        or data.get("authorized_argv") != expected_argv
        or type(data.get("returncode")) is not int
        or data["returncode"] != 0
        or data.get("decision") not in {"ALLOW", "SANDBOX"}
    ):
        raise ValueError(
            "observed command or exit status differs from the selected check"
        )


def validate_audit_mode(coverage, expected):
    if expected not in {"local", "external"} or coverage.get("audit_mode") != expected:
        raise ValueError(
            "authority audit profile does not match selected qualification"
        )


async def mcp_check(args):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=str(args.bridge),
        args=["--socket", str(args.socket), "--server-uid", str(args.server_uid)],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=150) as session:
            initialized = await session.initialize()
            menu = await session.list_tools()
            if args.tool not in {tool.name for tool in menu.tools}:
                raise ValueError("selected fixed tool was not advertised")
            result = await session.call_tool(args.tool, {})
            data = result.structured_content
            if result.is_error:
                raise ValueError(
                    "selected tool did not execute; inspect private authority audit"
                )
            validate_execution_result(data, args.expected_argv)
            return {
                "mcp_initialized": True,
                "tool_listed": True,
                "tool_executed": True,
                **({"expected_argv_and_zero_exit": True} if args.expected_argv else {}),
            }, {
                "protocol_version": initialized.protocol_version,
                "call_id": data.get("call_id"),
                "result_sha256": hashlib.sha256(
                    json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--server-uid", type=int, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--audit-mode", choices=("local", "external"), default="external"
    )
    parser.add_argument(
        "--expect-argv-json", help="Expected fixed process argv; also require exit zero"
    )
    args = parser.parse_args()
    args.expected_argv = None
    if args.expect_argv_json is not None:
        try:
            args.expected_argv = json.loads(args.expect_argv_json)
        except ValueError:
            parser.error("--expect-argv-json requires a JSON array of strings")
        if (
            not isinstance(args.expected_argv, list)
            or not args.expected_argv
            or any(not isinstance(x, str) or not x for x in args.expected_argv)
        ):
            parser.error("--expect-argv-json requires a nonempty array of strings")
    os.umask(0o077)
    report = {
        "status": "BLOCKED",
        "scope": "local connected tools; no native-agent containment",
        "checks": {},
        "enterprise_qualified": False,
        "audit_mode": args.audit_mode,
    }
    # Refuse to replace evidence, follow a symlink, or accidentally print output.
    fd = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        if os.geteuid() == 0 or os.geteuid() == args.server_uid:
            raise ValueError("use the separate enrolled non-root agent account")
        if not args.bridge.is_absolute() or not args.bridge.is_file():
            raise ValueError("absolute installed bull-mcp executable required")
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
        if dirty:
            raise ValueError("clean source required for recorded qualification")
        report.update(
            source_commit=revision, sdk_version=importlib.metadata.version("mcp")
        )

        def ipc(message):
            return request(args.socket, server_uid=args.server_uid, message=message)

        before = ipc({"method": "status"})
        if before.get("ok") is not True:
            raise ValueError("authority readiness failed")
        expected_tcb = hashlib.sha256(
            json.dumps(
                build_integrity_manifest(ROOT / "src/bulldog")["files"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if before["result"]["authority_tcb_sha256"] != expected_tcb:
            raise ValueError(
                "running authority does not match this source's trusted files"
            )
        report["authority_tcb_sha256"] = expected_tcb
        report["policy_sha256"] = before["result"]["policy_sha256"]
        report["checks"]["current_authority_source"] = True
        if before["result"]["coverage"]["whole_agent_contained"] is not False:
            raise ValueError("coverage mismatch")
        report["checks"]["coverage_disclosed"] = True
        validate_audit_mode(before["result"]["coverage"], args.audit_mode)
        report["checks"]["audit_profile_matches"] = True
        # Check rejected input through the real authority transport and verify
        # that it did not even consume an effect admission.
        spoof = ipc(
            {
                "method": "call",
                "name": args.tool,
                "arguments": {"argv": ["/bin/sh"]},
                "call_id": secrets.token_hex(16),
            }
        )
        after = ipc({"method": "status"})
        report["checks"]["spoof_has_no_admission"] = (
            spoof.get("ok") is False
            and after["result"]["lease"]["used_calls"]
            == before["result"]["lease"]["used_calls"]
        )
        if not all(report["checks"].values()):
            raise ValueError("negative admission check failed")
        checks, evidence = asyncio.run(mcp_check(args))
        report["checks"].update(checks)
        report.update(evidence)
        final = ipc({"method": "status"})
        report["checks"]["exactly_one_admission"] = (
            final.get("ok") is True
            and final["result"]["lease"]["used_calls"]
            == before["result"]["lease"]["used_calls"] + 1
            and final["result"]["lease"]["uncertain_calls"] == 0
        )
        if not all(report["checks"].values()):
            raise ValueError("post-execution admission accounting failed")
        report["status"] = (
            "LOCAL TOOL PASS" if args.audit_mode == "local" else "CONNECTED TOOL PASS"
        )
    except Exception as exc:
        report["reason"] = type(exc).__name__ + ": " + str(exc)[:512]
    with os.fdopen(fd, "w") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(args.output),
                "enterprise_qualified": False,
            }
        )
    )
    return 0 if report["status"] in {"LOCAL TOOL PASS", "CONNECTED TOOL PASS"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
