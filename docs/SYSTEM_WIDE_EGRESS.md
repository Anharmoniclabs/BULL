# System-Wide Egress Interception

This feature closes the "mediated-only" gap: previously BULL enforced
egress only for operations explicitly wired into its pipeline. Now every
outbound packet from the sandbox is either redirected into the BULL
gateway or dropped. There is no passthrough.

## Components

- `src/bulldog/egress_gateway.py` - transparent gateway: TLS ClientHello
  SNI enforcement (no MITM, no private keys), full plain-HTTP inspection
  with agent Authorization stripping, DNS allowlisting (REFUSED otherwise),
  fail-closed on every error path. Refuses to start without a policy.
- `src/bulldog/token_broker.py` - IAM-style proxy tokens: AES-256-GCM
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
- Vault persistence: the broker is in-memory at boot; provisioning
  host->guest (vsock) and an on-disk vault file are next steps.
- Gateway runs as user `bullgw`, the only egress-capable identity; that
  user is the trust anchor for the ruleset.
