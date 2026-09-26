# BULL lifecycle governance — experimental implementation v0.1

## Basis and scope

This implementation develops the owner-supplied September 26, 2026 design: 40
concerns, four planes (Authority, Execution, Observation, Sovereignty), and 15
invariants. Its research question remains: can an external authority architecture
avoid treating a model's internal alignment as the final security boundary?

The supplied text contains unresolved article citation placeholders. This build
uses it as a threat-model/design input, not as independently verified evidence
about any named frontier model or research incident.

**This is an experimental gate and executable conformance lab, not a production
firewall deployment.** It is additive to BULL, and does not replace or relax
`ProductionDispatcher`, `ProductionRuntime`, `SecurityDomainRegistry`, sandbox
attestation, signed policies, hardware approval or the existing audit system.
It does not start a model, run QEMU or access real credentials/weights.

Base inspected: `ui/bull-command-center-v1` at
`808c8fe5de47b9da3ac5ee2583f6ab1c1c7cb895`.

## Code and execution path

- `experiments/lifecycle_governance/core.py`: standard-library-only host-side gate.
- `tools/run_lifecycle_lab.py`: real, disposable local effects and a read-only
  evidence viewer. It never accepts browser commands.
- `experiments/lifecycle_governance/viewer.html`: readable evidence presentation.
- `tests/test_lifecycle_governance.py`: authorization, replay, provenance,
  lineage, cleanup, restart, tamper, concurrency and fault tests.
- `tests/test_lifecycle_lab.py`: actual fixture and read-only HTTP checks.
- `tools/check_lifecycle_browser.py`: optional offline Chromium render checks.

The gate's agent-facing call is `submit(EffectRequest, grant)`. It validates
canonical bytes, current lineage and provenance, resource class, exact scope,
adapter schema, approval, expiry and one-use state. It commits the admission
record and consumed grant **before** invoking the typed adapter. Completion is
recorded separately. No adapter means no effect. There is no generic fallback.

`inspect()` is only a policy inspection: it does not authorize or execute anything.
A browser replay likewise replays recorded evidence; it is not a new gate call.

## The four planes, implemented

### Authority

`EffectRequest` binds actor, effect kind, registered target, exact parameters and
request ID. Canonical encoding rejects duplicate wire keys, extra authority
fields, oversized values, non-string keys, floats and unsupported object types.
Host grants carry the complete effect digest, expiry and current lineage/context
stamp. Grants and request IDs are single-use; minting a second token does not
make the same request executable twice.

Host-only provisioning creates roots and children. Child scopes must be a proper
subset, inherit the root, cannot outlive their ancestors, and have bounded depth.
Agent-controlled identities remain tied to one root; aliases do not create new
independent roots. Message schemas bind identity, purpose and body alongside the
registered destination. A root-wide budget of ten messages/publications per
minute applies across aliases and cannot be bypassed by approval.

`approve()` is an **explicit host API approval**, not evidence of human presence.
The deterministic display and approval bind the same canonical request digest
and lineage stamp. They are groundwork for BULL's independent approval device,
not a substitute for that device. Model prose is never an approval credential.

### Execution

All effect handlers are explicitly registered by the host with an exact parameter
schema and allowed resource classes. Requests reference immutable host registry
IDs, not arbitrary host paths. Protected model state cannot be laundered into
ordinary reads; it requires `REPLICATE`. Durable state requires `PERSIST`.
Credential resources require `CREDENTIAL_USE`. Security-control resources and
`SECURITY_CONTROL` are never grantable to agent domains.

The lab provides only bounded, synthetic read/persist fixtures. An export fixture
must never be entered in the rejected-copy scenario. No network, shell, arbitrary
Python, real message delivery, secret broker or model loader is installed by
default. Registering an arbitrary callable is a trusted deployment operation,
not something an agent may do.

### Observation

Sources carry owner/root, content digest, parent IDs, trust and expiry. Derivation
cannot raise trust above any parent. Root-wide accumulated provenance is deliberately
conservative: omitting a source from a later proposal cannot erase it. New observed
context changes the root's context version, invalidating earlier grants/approvals.
This is not a semantic detector capable of discovering all undisclosed influences.

Authenticated effect denials are counted per root. The configured threshold freezes
a root and descendants. Invalid tokens do not let a caller freeze a victim simply
by asserting the victim's actor ID. Fleet correlation groups actual admitted target
fingerprints across distinct roots, not aliases. It produces `OBSERVE`/`REVIEW`
evidence only; it never grants authority or declares an actor malicious.

The local SQLite state and append-only event sequence use domain-separated HMACs.
State updates are serialized with `BEGIN IMMEDIATE`. Events, head and consumed grants
are committed together. An admission lacking a successful completion is an unresolved
effect; reopening the gate detects it and refuses new effects rather than retrying.

### Sovereignty

Host freeze revokes an entire root lineage and advances each domain's epoch before
cleanup begins. Existing approvals become unusable. All owned resources become
`revocation_pending`, then `revoked` only when a host-owned revoker confirms success.
Unsupported or failed revocation remains visible. Shutdown freezes first, invokes a
host-owned termination callback, and only then attempts resource cleanup. The lab
actually terminates a harmless subprocess it created; it accepts no arbitrary PID.

**Admission is the linearization boundary.** Revocation prevents later admissions;
it cannot retroactively undo or guarantee cancellation of already admitted effects.
The test suite explicitly checks that freeze need not wait for a running adapter.
Production integrations need out-of-process deadline/cancellation supervisors and
broker-specific revocation. A callback that hangs is not a completed shutdown.

## Run the build

From the repository root, Python 3.10+ and the standard library suffice for the lab:

```bash
python3 tools/run_lifecycle_lab.py --output /tmp/bull-lifecycle-evidence --serve --port 11511
```

In Codespaces, open the private forwarded **11511** port printed by the launcher.
The existing command center on **11510** is not replaced. The viewer serves only
its generated HTML. It does not expose the state database, key, files or a POST
API. The generated HTML also works as a standalone artifact in a normal browser.

The script writes a fresh run directory each time. The directory contains a
private host signing key and database: do not upload or commit either. The HTML
and evidence JSON contain no grants or key material. JSON is an evidence format,
not the user interface. If the port is occupied, select a different `--port`.

Tests:

```bash
python -m pytest -q tests/test_lifecycle_governance.py tests/test_lifecycle_lab.py
```

Optional browser rendering, after installing Playwright/Chromium in the test host:

```bash
python tools/check_lifecycle_browser.py /path/to/run/index.html
```

The browser test renders supplied HTML offline. HTTP routing is independently
tested with real local requests. No browser policy is disabled.

## Required before production integration

1. **One authority source.** Bind lifecycle domain IDs to BULL's existing trusted
   `SecurityDomainRegistry` identities; do not accept roots asserted in model text.
   Revocation must gate every path, including direct broker consumers.
2. **No second execution route.** A process adapter must call the real
   `ProductionDispatcher`, retaining full argv binding, signed policy, required
   malware admission, sandbox proof and audit gates. Do not wire a callable shell
   adapter directly into this experiment and label it production.
3. **Independent approval and audit.** Feed the canonical display into BULL's
   existing hardware approval flow and publish authenticated external checkpoints.
   The lab's host API and local HMACs do not establish either requirement.
4. **Lifecycle closure.** Supply tested termination and revocation adapters for
   every issued credential, account, scheduled task, child worker, cloud resource
   and state copy. Exercise provider failures, timeout, restart and disconnected
   operation. Pending cleanup is a blocker, not a green check.
5. **Qualification.** Run the full existing security/regression suite, real KVM
   probes, multi-process race tests, fuzzing, bypass enumeration and independent
   review. Do not infer any of those results from this lab's pass count.

## Explicit limitations

A Python object identity check separates host APIs but cannot defend against
hostile Python in the same interpreter. The key, database, callbacks and governor
must run outside the untrusted agent. This experiment does not install an OS
boundary or intercept arbitrary host I/O.

A complete rollback of database plus earlier valid authenticated state is not
detectable without an independent latest checkpoint. Local HMAC validity is not
remote freshness or third-party non-repudiation. The viewer reports verification
at generation time; its HTML can be edited and is not itself attested.

Conservative root-wide provenance can over-restrict legitimate work. There is no
trusted declassification path in v0.1. There is also no semantic lie detector,
beneficiary-mismatch detector, retaliation detector or trained agent monitor.

The state is an authenticated bounded snapshot, not a scalable production ledger:
16 KiB request encoding, 8 MiB state, 20,000 events, eight lineage levels. Capacity
exhaustion fails closed. Deployments need a bounded storage/rotation design that
preserves an independent checkpoint before lifting these limits.

This is scoped lifecycle evidence, **not** proof of universal prompt-injection
prevention, universal anti-reconstitution or protection against a compromised host.
