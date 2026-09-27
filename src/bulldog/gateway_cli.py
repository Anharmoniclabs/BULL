"""Operator commands. Registration is explicit and never claims containment."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import time


def add_parser(commands):
    gateway = commands.add_parser(
        "gateway", help="Fixed-tool local gateway; connected mode only"
    )
    sub = gateway.add_subparsers(dest="gateway_command", required=True)
    service = sub.add_parser(
        "serve", help="Start trusted authority under a separate non-root OS account"
    )
    service.add_argument("--state", type=Path, required=True)
    service.add_argument("--socket", type=Path, required=True)
    service.add_argument("--agent-gid", type=int, required=True)
    service.add_argument("--egress-socket", type=Path)
    service.add_argument(
        "--audit-mode", choices=("local", "external"), default="external"
    )
    service.set_defaults(handler=run_service)
    broker = sub.add_parser(
        "broker", help="Run a separate private egress broker from the signed registry"
    )
    broker.add_argument("--socket", type=Path, required=True)
    broker.set_defaults(handler=run_broker)
    config = sub.add_parser(
        "client-config", help="Print registration JSON; does not change client settings"
    )
    config.add_argument("--socket", type=Path, required=True)
    config.add_argument("--server-uid", type=int, required=True)
    config.add_argument("--bridge", type=Path, required=True)
    config.add_argument("--client", choices=("claude", "codex"), required=True)
    config.set_defaults(handler=client_config)
    check = sub.add_parser(
        "check",
        help="As agent UID, check the real authority connection without executing a tool",
    )
    check.add_argument("--socket", type=Path, required=True)
    check.add_argument("--server-uid", type=int, required=True)
    check.set_defaults(handler=check_connection)
    revoke = sub.add_parser(
        "revoke", help="Stop future admissions for one private lease"
    )
    revoke.add_argument("--state", type=Path, required=True)
    revoke.set_defaults(handler=revoke_session)
    coverage = sub.add_parser(
        "coverage", help="Show implementation status and outstanding enterprise gates"
    )
    coverage.set_defaults(handler=show_coverage)


def show_coverage(args):
    from importlib.resources import files

    print(files("bulldog").joinpath("data/agent_gateway_release.json").read_text())
    return 0


def _nonroot_authority():
    if os.geteuid() == 0:
        raise ValueError("authority service must run as its dedicated non-root account")
    os.umask(0o077)


def run_service(args):
    from .agent_gateway import COVERAGE, GatewayAuthority
    from .egress_proxy import EgressClient
    from .gateway_transport import GatewayServer
    from .profiles import (
        LocalDispatcher,
        LocalRuntime,
        ProductionDispatcher,
        ProductionRuntime,
    )

    authority = server = None
    try:
        _nonroot_authority()
        audit_mode = getattr(args, "audit_mode", "external")
        if audit_mode not in {"local", "external"}:
            raise ValueError("unknown audit profile")
        if audit_mode == "local" and args.egress_socket:
            raise ValueError("local audit profile has no egress broker")
        runtime = LocalRuntime() if audit_mode == "local" else ProductionRuntime()
        egress = (
            EgressClient(args.egress_socket, os.geteuid())
            if args.egress_socket
            else None
        )
        dispatcher = LocalDispatcher if audit_mode == "local" else ProductionDispatcher
        authority = GatewayAuthority(
            dispatcher(runtime=runtime, egress_broker=egress), args.state
        )
        server = GatewayServer(authority, args.socket, agent_gid=args.agent_gid)
        signal.signal(signal.SIGTERM, lambda *_: server.close())
        print(
            json.dumps({"status": "LISTENING", "coverage": authority.coverage}),
            flush=True,
        )
        server.serve()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": type(exc).__name__,
                    "detail": "Authority startup or service failed; inspect private deployment checks.",
                }
            )
        )
        return 1
    finally:
        if server is not None:
            server.close()
        if authority is not None:
            authority.close()


def run_broker(args):
    from urllib.parse import urlsplit
    from .agent_session import private_directory
    from .agent_tool_registry import available_tools, validate_gateway_config
    from .egress_proxy import EgressBroker
    from .policy_bundle import load_policy_bundle

    broker = None
    try:
        _nonroot_authority()
        private_directory(args.socket.parent)
        if args.socket.exists() or args.socket.is_symlink():
            raise ValueError("refusing existing broker endpoint")
        bundle = load_policy_bundle(
            os.environ["BULL_POLICY_BUNDLE"], os.environ["BULL_POLICY_BUNDLE_KEY"]
        )
        config = validate_gateway_config(bundle.raw.get("agent_gateway"))
        if config["agent_uid"] == os.geteuid():
            raise ValueError("agent and broker must use separate UIDs")
        tools = available_tools(config, bundle.capability_ceiling)
        broker = EgressBroker(
            args.socket,
            allowed_hosts={
                urlsplit(x["url"]).hostname
                for x in tools.values()
                if x["operation"] == "network.request"
            },
            require_peer_credentials=True,
            allowed_peer_uids={os.geteuid()},
        )
        broker.start()

        def stop(*_):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)
        while time.time() < config["expires_at"]:
            time.sleep(0.5)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        print(json.dumps({"status": "BLOCKED", "detail": "broker startup failed"}))
        return 1
    finally:
        if broker is not None:
            broker.stop()


def client_config(args):
    from .agent_gateway import COVERAGE

    if (
        not args.bridge.is_absolute()
        or not args.socket.is_absolute()
        or args.server_uid <= 0
    ):
        raise ValueError("absolute bridge/socket and non-root authority UID required")
    value = {
        "command": str(args.bridge),
        "args": ["--socket", str(args.socket), "--server-uid", str(args.server_uid)],
    }
    print(
        json.dumps(
            {
                "mcpServers" if args.client == "claude" else "mcp_servers": {
                    "bull": value
                },
                "bull_coverage": COVERAGE,
            },
            indent=2,
        )
    )
    return 0


def check_connection(args):
    from .gateway_transport import request

    try:
        value = request(
            args.socket, server_uid=args.server_uid, message={"method": "status"}
        )
        print(json.dumps(value, indent=2))
        return 0 if value.get("ok") is True else 1
    except Exception:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "detail": "authenticated authority connection failed",
                }
            )
        )
        return 1


def revoke_session(args):
    from .agent_session import private_directory, private_file

    directory = private_directory(args.state)
    fd = private_file(directory / "REVOKED")
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(
        json.dumps(
            {
                "status": "REVOKED",
                "scope": "future admissions; already dispatched work can finish",
            }
        )
    )
    return 0
