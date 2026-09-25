"""Production entrypoint: wire policy + token broker + gateway together.

Reads an egress policy JSON from /etc/bull/egress_policy.json and starts
the transparent gateway. Fails closed: any missing configuration is a
hard error, never a silent open relay.

Upstream secrets are provisioned out-of-band (e.g. by the host over
vsock during guest build) via TokenBroker.store_upstream_secret; the
agent never sees them.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .egress_gateway import EgressGateway, EgressPolicy, GatewayConfig
from .token_broker import TokenBroker


def load_policy(path: str) -> EgressPolicy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        sys.exit(f"fail-closed: policy file {path} missing")
    except json.JSONDecodeError as exc:
        sys.exit(f"fail-closed: policy file {path} unparseable: {exc}")
    hosts = cfg.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        sys.exit("fail-closed: policy has empty/missing hosts allowlist "
                 "(deny-all is the intended default; edit the policy file)")
    return EgressPolicy(hosts)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="bull-egress-gateway")
    ap.add_argument("--policy", default="/etc/bull/egress_policy.json")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--transparent-port", type=int, default=9443)
    ap.add_argument("--dns-port", type=int, default=953)
    ap.add_argument("--dns-upstream", default="127.0.0.53")
    args = ap.parse_args(argv)

    policy = load_policy(args.policy)

    # Token broker: real upstream credentials live behind the gateway.
    # The vault is provisioned by the operator via
    # TokenBroker.store_upstream_secret; persistent vault-file loading is
    # the next integration step (see docs/SYSTEM_WIDE_EGRESS.md).
    broker = TokenBroker()

    def inject(req):
        # Only inject when the broker actually holds a secret for the
        # destination; otherwise the request goes out unauthenticated
        # (still policy-gated).
        if req.host in broker.upstream_secret_names():
            token, _ = broker.mint("egress-gateway", "NETWORK_EGRESS",
                                   req.host, ttl=60.0)
            secret = broker.exchange(token, "NETWORK_EGRESS", req.host)
            return {"Authorization": "Bearer " + secret.decode("utf-8", "replace")}
        return {}

    host, _, port = args.dns_upstream.rpartition(":")
    cfg = GatewayConfig(listen_host=args.listen,
                        transparent_port=args.transparent_port,
                        dns_port=args.dns_port,
                        dns_upstream=(host or "127.0.0.53", int(port or 53)))
    gw = EgressGateway(policy, cfg, header_injector=inject)

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
