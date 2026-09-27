# System-Wide Egress Interception

This is a candidate for a dedicated guest network boundary. A filter chain
drops unapproved output and a NAT chain redirects HTTP, TLS and DNS to the
gateway. This branch alone does not prove universal interception on a booted
guest; the installer must be exercised with IPv4/IPv6 and route-bypass probes.

## Components

- `src/bulldog/egress_gateway.py` - transparent gateway: TLS ClientHello
  SNI enforcement (no MITM, no private keys), full plain-HTTP inspection
  with agent Authorization stripping, DNS allowlisting (REFUSED otherwise),
  fail-closed on every error path. Refuses to start without a policy.
- `src/bulldog/token_broker.py` - optional prototype (install with
  `.[egress]`), not used by the transparent service: AES-256-GCM
  upstream-secret vault, HMAC-SHA256 signed short-lived tokens
  (capability-scoped, target-scoped, TTL-bound, revocable), epoch-based
  key rotation with grace windows, revoke_all kill-switch.
- `src/bulldog/semantic_intent.py` - deterministic semantic intent gate:
  k-NN over hashed char n-grams mapping NL requests to capability hints.
  Hints can only narrow or escalate, never expand; destructive-verb floor
  forbids read-class hints on destructive requests.
- `src/bulldog/run_egress_gateway.py` - production entrypoint (fails
  closed on missing/empty policy).
- `deploy/egress_redirect.nft` - fail-closed nftables ruleset (guest).
- `deploy/install_egress_gateway.sh` - one-shot production adapter.
- `deploy/bull-egress-gateway.service` - hardened systemd unit.

## Verification

40/40 tests passing (`tests/test_semantic_intent.py`,
`tests/test_token_broker.py`, `tests/test_egress_gateway.py`), including
real-socket, real-TLS end-to-end tests and a live DNS transport check
(REFUSED for non-allowlisted names).

Run: `PYTHONPATH=src pytest tests/test_semantic_intent.py
tests/test_token_broker.py tests/test_egress_gateway.py`

## Known limits (honest)

- Transparent mode enforces on SNI, not TLS payloads. No MITM by design.
- The nftables ruleset is validated at install time (`nft -c`) and must
  be exercised in a real Linux guest; it is not executed in unit tests.
- Credentialed requests stay on the existing identity-bound BULL broker.
  TokenBroker is a separate in-memory prototype; this service does not load
  secrets or use it as an ambient credential authority.
- TLS permits only host-level rules; method/path-scoped hosts are denied on
  opaque TLS. No encrypted request-body inspection is claimed.
- The default installed policy is deny-all; explicitly configure hosts
  before starting. The filter chain remains installed when the service stops.
- Gateway runs as user `bullgw`, the only egress-capable identity; that
  user is the trust anchor for the ruleset.

The installer is restricted to a **dedicated guest**. It validates an operator
configured nonempty allowlist before changing network rules, and retains the
filter if the gateway stops. The service reads a root-owned installed ruleset,
not the possibly writable source checkout; policy is root-owned and readable
by the `bullgw` group. Its nftables NAT/filter rules have not passed a
current real-guest escape test. A present gateway process or successful host
unit tests must never be shown as guest enforcement. The `bullgw` identity is
trusted; any process that obtains this identity can bypass the redirect.
