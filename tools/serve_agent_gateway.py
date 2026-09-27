#!/usr/bin/env python3
"""Load private deployment authority and run BULL's connected-tool service.

Run from the reviewed installation as the dedicated authority account. The
agent's MCP configuration must never contain this command or deployment path.
"""

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from tools.deployment_setup import isolated_environment
from bulldog.gateway_cli import run_service, run_broker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--agent-gid", type=int)
    parser.add_argument("--egress-socket", type=Path)
    parser.add_argument("--broker", action="store_true")
    args = parser.parse_args()
    if not args.broker and (args.state is None or args.agent_gid is None):
        parser.error("authority requires --state and --agent-gid")
    if os.geteuid() == 0:
        parser.error("run as the dedicated non-root authority user")
    environment = isolated_environment(args.deployment)
    os.environ.clear()
    os.environ.update(environment)
    args.audit_mode = environment.get("BULL_AUDIT_MODE", "external")
    if args.broker and args.audit_mode == "local":
        parser.error("local audit profile has no external broker")
    return run_broker(args) if args.broker else run_service(args)


if __name__ == "__main__":
    raise SystemExit(main())
