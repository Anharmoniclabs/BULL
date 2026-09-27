# Reading BULL's code

BULL separates a request from the authority to carry it out. To understand a
path, ask: who supplied the request, who granted permission, what changes outside
the process, and what is recorded if it fails?

## The main responsibilities

| File | Responsibility | Important boundary |
|---|---|---|
| `src/bulldog/production_router.py` | Route three named effect types to the production dispatcher | Rejects unknown operations; does not intercept arbitrary Python calls |
| `src/bulldog/profiles.py` | Apply production dispatch requirements and invoke execution or brokers | Holds policy checks and the broker approval/journal path |
| `src/bulldog/dispatcher.py` | Define requests and dispatch decisions | A request is not itself an authorization |
| `src/bulldog/effect_journal.py` | Record an effect before dispatch and retain uncertain outcomes | Prevents automatic redispatch of a consumed key; does not guarantee remote exactly-once delivery |
| `src/bulldog/egress_gateway.py` | Inspect supported HTTP, TLS SNI and DNS requests | TLS payloads remain opaque; gateway identity is trusted |
| `src/bulldog/qualification.py` | Read selected private reports for the console | Reports must match the expected checks and source revision |
| `deploy/egress_redirect.nft` | Redirect selected guest traffic and drop other output | Applies inside the configured guest; `bullgw` bypasses the filter |
| `deploy/bull-egress-gateway.service` | Start and constrain the gateway service | Service startup alone does not prove network enforcement |

Paths in this table are relative to the repository root. Read the code alongside
[the security model](PRODUCTION_SECURITY.md), which describes the wider runtime.

## Follow one production effect

`ProductionEffectRouter.dispatch` accepts a `ProductionEffect`. It checks the
operation and parameter names before calling one of three dispatcher methods:

| Operation | Parameters | Dispatcher method |
|---|---|---|
| `process.execute` | `argv`, `project_root`, `timeout` | `execute` |
| `network.request` | `url`, `method`, `headers`, `body` | `fetch_egress` |
| `secret.read` | `token`, `name`, `sandbox_id` | `get_secret` |

These are the router's current input fields, not evidence that every route is
working. The network route passes `headers` and `body` to a dispatcher method
that does not accept them. The network and secret routes also omit the explicit
domain identity required by a domain-enabled dispatcher. The
[enterprise agent gateway plan](ENTERPRISE_AGENT_GATEWAY_PLAN.md) records these
contract fixes and their test requirements before adding an MCP interface.

Unknown operations are denied at this entry point. This is a coverage boundary:
other adapters must deliberately use it before they can inherit its checks.
Process authority comes through signed policy and dispatch state. Broker effects
use the approval path in `profiles.py`; policy-authorized routine GET/HEAD requests
have an explicit exception. Do not describe every network call as requiring a
new human signature.

## Follow an external effect that needs approval

Read `_perform_broker_effect` in `profiles.py`, then `DurableEffectJournal.begin`.
The ordering matters: the journal consumes the effect key before the external
call. A successful call is recorded as confirmed. An uncertain outcome requires
trusted reconciliation, rather than an automatic repeat that could duplicate an
action. The remote service still needs its own idempotency contract to support
an exactly-once delivery claim.

The journal is durable SQLite state. Its transaction boundaries, audit callbacks
and error paths are part of the behavior, not formatting details.

## Follow the combined guest test

1. `tools/run_codespace_combined_candidate_kvm.py` runs the direct-init lab, then
   creates a systemd candidate from it.
2. `tools/run_codespace_gateway_kvm.py` builds and boots the disposable guest.
3. `tools/run_codespace_gateway_systemd_kvm.py` stages the actual BULL service
   units in a cloned guest and boots systemd.
4. `tools/gateway_guest_probe.py` checks gateway identity, traffic handling,
   blocked alternatives, and behavior while the gateway stops and restarts.
5. The combined runner requires all 13 named checks before reporting
   `CANDIDATE PASS`.

These probes use controlled test traffic. They do not run the complete
`ProductionEffectRouter` / `ProductionDispatcher` workload path in a released
production image. Read the report's scope before interpreting its PASS.

## Read a console result

`qualification.py` turns operator-selected reports into small status objects.
`PASS`, `STALE`, `INVALID` and `UNVERIFIED` answer different questions. An old
passing report can be stale for a new revision; an invalid report is not proof
that the runtime failed; an absent report is not proof that a feature is safe.
The console is an evidence reader, not an independent auditor.

## Where to test a change

- Router schemas and denial paths: `tests/test_production_router.py`.
- Effect ordering and reconciliation: `tests/test_effect_journal.py`.
- Report acceptance and source binding: `tests/test_qualification.py`.
- Gateway behavior: `tests/test_egress_gateway.py`.
- Assurance logic: `tests/test_assurance.py`.

Use these with the contributor guide. Source tests and a real KVM qualification
answer different questions; neither should be reported as the other.
