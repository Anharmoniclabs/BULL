# BULL Multi-Agent System

The `bulldog.multiagent` package extends BULL's mission — **Blocking
Unauthorized Logic Loopholes** — to the orchestration layer. Instead of a
single agent with full tool access, work is decomposed across specialized
agents, and every step must pass independent gates before and after
execution.

## Architecture

```
             host-owned per-run canary
                       |
                       v
                 +--------------+
   task -------> | Coordinator  |  normalizes the task into a plan,
                 +------+-------+  blocks injected tasks up front
                        |
                        v
                 +--------------+
                 |    Policy    |  allowlist-first, default-deny verdict
                 +------+-------+  per step
                        |
                  ALLOW |  DENY -> recorded, never executed
                        v
                 +--------------+
                 |   Executor   |  runs registered callables only
                 +------+-------+  (no eval/exec), requires ALLOW token
                        |
                        v
              +---------------------+
              | Auditor + Verifier  |  independent scans of every output;
              +----------+----------+  unverified results are discarded
                         |
                         v
                    RunReport

   HoneyTokenAgent + MessageBus boundary guard inspect every envelope/result.
   A canary outside its one trusted-context field hard-stops the trace.
```

All messages travel on a capability-checked `MessageBus` that records a
`TraceEvent` for every delivery, enforces a hop limit to stop loops, and can
run a host-owned boundary guard before delivery and after every handler
result.

## Agents

| Agent | Capability | Responsibility |
| --- | --- | --- |
| HoneyTokenAgent | `honeytoken` | Mint a per-run inert canary and hard-stop leakage across bus/result/write boundaries |
| CoordinatorAgent | `coordinate` | Task normalization, plan ordering, upfront injection scan |
| PolicyAgent | `policy` | First-match-wins rule evaluation, default deny |
| ExecutorAgent | `execute` | Runs allow-listed callables, refuses unapproved steps |
| AuditorAgent | `audit` | Scans intermediate payloads for unauthorized logic |
| VerifierAgent | `verify` | Independent post-execution output gate |

## Canary boundary

For every run, the host mints a high-entropy marker such as a
`BULL-CANARY-v1:...` value. It is not a credential and grants no authority.
The raw value is permitted only in the initial trusted context delivered to
the coordinator/model adapter:

```text
system -> coordinator
payload.trusted_context.canary
```

The `MessageBus` invokes the honeytoken guard:

1. before every envelope is delivered;
2. after every agent result is returned;
3. on adapter-owned persistence/output when the integration calls
   `system.guard_external_write(...)`.

The guard checks the raw marker, the high-entropy body, URL encoding, hex,
base64/base64url forms, and a reconstruction of adjacent structured string
values. A hit produces a `CRITICAL` `honeytoken.leak` finding, records only a
SHA-256 fingerprint of the token, permanently trips the trace, suppresses
contaminated step output, and blocks later bus delivery for that trace.
Cross-run leakage trips both the receiving trace and the trace that owns the
leaked canary.

Boundary scanning itself is bounded. If a payload is too large to inspect
within the configured character budget, the trace fails closed with
`honeytoken.scan-overflow` rather than treating an uninspected payload as
safe.

### Adapter rule

A real LLM adapter should place `payload["trusted_context"]` in trusted model
context and must route any memory/cache/external write through the guard before
committing it:

```python
system.guard_external_write(
    report.trace_id,
    proposed_memory,
    channel="conversation-memory",
)
```

Do not log the raw canary and do not use real AWS/Stripe/API credentials as
honeytokens. BULL's built-in marker is synthetic and inert.

### What the canary does *not* prove

A canary is evidence of extraction or context leakage when it appears where it
should not. Its absence is **not** proof that a run is benign. An action-oriented
attack can avoid reproducing the marker entirely. Arbitrary encryption,
semantic transformation, or lossy rewriting can also defeat exact marker
matching. BULL therefore keeps canaries as an independent detection layer on
top of deterministic policy, one-time execution approval, broker controls,
sandboxing, domain authority, auditor/verifier checks, and the production
runtime boundary.

## Usage

```python
from bulldog.multiagent import MultiAgentSystem

system = MultiAgentSystem(
    actions={"echo": lambda text="": text, "sum": lambda a=0, b=0: a + b}
)
report = system.run({"action": "sum", "args": {"a": 2, "b": 3}})
print(report.verdict, report.to_dict())
```

Tasks carrying unauthorized-logic markers (prompt injection patterns,
destructive commands, exfiltration language) are blocked by the
coordinator before any step executes; unknown actions are denied by the
policy agent; outputs are re-scanned by both the auditor and verifier; and the
host-owned canary provides a separate, non-semantic signal if trusted context
is reproduced downstream.

## Extension points

- Register additional callables with `system.register_action`.
- Pass custom `PolicyRule` sequences to `MultiAgentSystem(policy_rules=...)`.
- Add agents by subclassing `BaseAgent` and registering them on the bus.
- Route adapter-owned memory/output writes through `system.guard_external_write`.
- Stream `system.bus.trace()` into bulldog's audit layer for persistence. Raw
  canaries are intentionally never written to trace events.

The package is stdlib-only and self-contained so it can run with or
without the rest of the bulldog runtime.
