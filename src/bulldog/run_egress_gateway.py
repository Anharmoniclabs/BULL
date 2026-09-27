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
import ipaddress
import json
import sys

from .egress_gateway import EgressGateway, EgressPolicy, GatewayConfig


def parse_dns_upstream(value: str) -> tuple[str, int]:
    """Accept an IP literal with an optional port; IPv6 ports use brackets."""
    if value.startswith("["):
        host, closing, suffix = value[1:].partition("]")
        if not closing or (suffix and not suffix.startswith(":")):
            raise ValueError("invalid DNS upstream address")
        port_text = suffix[1:] if suffix else "53"
    else:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            host, separator, port_text = value.rpartition(":")
            if not separator:
                raise ValueError("DNS upstream must be an IP address") from None
        else:
            host, port_text = value, "53"
    try:
        ipaddress.ip_address(host)
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("invalid DNS upstream address or port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("DNS upstream port out of range")
    return host, port


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

    try:
        dns_upstream = parse_dns_upstream(args.dns_upstream)
    except ValueError as exc:
        ap.error(str(exc))
    cfg = GatewayConfig(listen_host=args.listen,
                        transparent_port=args.transparent_port,
                        dns_port=args.dns_port,
                        dns_upstream=dns_upstream)
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
