"""Guest entrypoint for the transparent egress gateway.

Reads an egress policy JSON from /etc/bull/egress_policy.json and starts
the transparent gateway. Fails closed: any missing configuration is a
hard error, never a silent open relay.

Transparent sockets lack a verified actor identity, so this runner does not
attach shared upstream secrets. Credentialed effects need a separate
identity-bound host broker.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .egress_gateway import EgressGateway, EgressPolicy, GatewayConfig


def load_policy(path: str) -> EgressPolicy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"fail-closed: policy file {path} missing")
    except json.JSONDecodeError as exc:
        sys.exit(f"fail-closed: policy file {path} unparseable: {exc}")
    hosts = cfg.get("hosts") if type(cfg) is dict else None
    if not isinstance(hosts, dict) or not hosts:
        sys.exit("fail-closed: policy has empty/missing hosts allowlist "
                 "(deny-all is the intended default; edit the policy file)")
    return EgressPolicy(hosts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bull-egress-gateway")
    ap.add_argument("--policy", default="/etc/bull/egress_policy.json")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--transparent-port", type=int, default=9443)
    ap.add_argument("--dns-port", type=int, default=1953)
    ap.add_argument("--dns-upstream", default="127.0.0.53")
    ap.add_argument("--check-policy", action="store_true", help="Validate configured policy and exit")
    args = ap.parse_args(argv)

    policy = load_policy(args.policy)
    if args.check_policy:
        return 0

    # Transparent sockets carry no authenticated actor identity. This runner
    # therefore never injects upstream credentials from a shared vault.
    # Credentialed effects must use BULL's identity-bound broker path.

    host, _, port = args.dns_upstream.rpartition(":")
    cfg = GatewayConfig(listen_host=args.listen,
                        transparent_port=args.transparent_port,
                        dns_port=args.dns_port,
                        dns_upstream=(host or "127.0.0.53", int(port or 53)))
    gw = EgressGateway(policy, cfg)

    async def serve():
        await gw.start()
        print(f"bull egress gateway: transparent={args.listen}:{args.transparent_port} "
              f"dns={args.dns_port} hosts={sorted(policy._rules)}", flush=True)
        await asyncio.Event().wait()  # run until stopped

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
