# BULL Multi-Agent System

The `bulldog.multiagent` package extends BULL's mission — **Blocking
Unauthorized Logic Loopholes** — to the orchestration layer. Instead of a
single agent with full tool access, work is decomposed across specialized
agents, and every step must pass independent gates before and after
execution.

## Architecture

```
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
                    RunReport (full audit trail + bus trace)
```

All messages travel on a capability-checked `MessageBus` that records a
`TraceEvent` for every delivery and enforces a hop limit to stop loops.

## Agents

| Agent | Capability | Responsibility |
| --- | --- | --- |
| CoordinatorAgent | `coordinate` | Task normalization, plan ordering, upfront injection scan |
| PolicyAgent | `policy` | First-match-wins rule evaluation, default deny |
| ExecutorAgent | `execute` | Runs allow-listed callables, refuses unapproved steps |
| AuditorAgent | `audit` | Scans intermediate payloads for unauthorized logic |
| VerifierAgent | `verify` | Independent post-execution output gate |

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
policy agent; and outputs are re-scanned by both the auditor and the
verifier before the run is reported as allowed.

## Extension points

- Register additional callables with `system.register_action`.
- Pass custom `PolicyRule` sequences to `MultiAgentSystem(policy_rules=...)`.
- Add agents by subclassing `BaseAgent` and registering them on the bus.
- Stream `system.bus.trace()` into bulldog's audit layer for persistence.

The package is stdlib-only and self-contained so it can run with or
without the rest of the bulldog runtime.
