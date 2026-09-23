# Supported execution paths and recovery evidence

Production support is specific to an execution path. Passing orchestration or
model-selection tests does not establish containment of arbitrary host callables.

| Entry point | Enforcement and scope | Validation |
|---|---|---|
| `tools/governed_agent.py` | ProductionDispatcher / ProductionRuntime; two fixed read-only tools in host NamespaceSandbox; trusted host supervisor and local model | `test_governed_agent.py`; `check_agent_dispatch.py` exercises both tools and empty-grant denial on an actual deployment; `check_governed_agent.py` covers model proposals and two worker exits |
| `src/bulldog/guest_engine.py` | ProductionDispatcher / ProductionRuntime inside a fresh KVM guest; host-authorized command and session | `test_guest_engine.py`, `test_microvm_protocol.py`; `microvm/integration.py --case all` tests allowed, denied, timeout, cancellation and missing protections |
| ProductionDispatcher API | Host-owned exact command and authority; each integrating application must mediate its own effects | Production-boundary, full-argv, approval and broker tests; these are not evidence for an unreviewed external adapter |
| `bulldog.multiagent.MultiAgentSystem` and its example | Development orchestration; registered callables execute in the host Python process; not automatically connected to ProductionDispatcher | Multiagent tests cover bus/policy/canary behavior only; not a production effect adapter |
| `bull` CLI and agent sentinel | Evaluation/advisory surfaces; not independent production execution adapters | Policy and sentinel tests do not establish containment |
| External agent frameworks | No blanket integration claim | Require an adapter inventory and positive/negative effect tests before claiming support |

## Controlled recovery checks

`tests/test_recovery_failures.py` adds a real disposable loopback TLS collector
outage and restart using its retained SQLite database, explicit audit reconciliation,
idempotent checkpoint retry, and continuation. It also tests a dedicated worker
exiting with a pending plan, a bounded ledger refusing additional records, and
injected ENOSPC/EIO at append/head-write boundaries. Storage faults are injected;
the tests do not fill a disk or simulate a physical storage controller.

An append failure before writing preserves a valid ledger. A record written before
its head checkpoint fails blocks later appends and preserves the inconsistent
evidence for investigation. Automatic repair or deletion of such history is not
supported. Remote reconciliation retries audit delivery, not workload effects.

These tests do not establish machine power-loss durability, OS reboot recovery,
persistent VM restart, or production collector disaster recovery. A fresh guest
after a cancelled guest is a separate one-shot session, not recovery of guest RAM
or an interrupted side effect. Host reboot testing requires a disposable host
that does not contain the active operator/chat session.

## Candidate identity

Commit all implementation changes before invoking `tools/deployment_check.py`.
Keep its source identity, pinned kernel/rootfs/firmware hashes, per-guest runtime
tree hashes, local regression and exact-head CI results together outside Git.
Do not edit the candidate during the run. The checker verifies source and image
identity and reports physical-key validation separately as BLOCKED when absent.
An evidence-only follow-up commit is not the commit tested by those live checks.

Use a new deployment for `tools/check_agent_dispatch.py` with the governed fixture
as project root. Its final denied request belongs in that deployment's behavioral
history; do not erase it to reuse the deployment for another acceptance run.
The live collector is distinct from the rejected preview; no preview promotion
is part of this procedure.
