# BULL

**BULL** is an experimental open-source, model-agnostic execution-governance runtime for AI agents.

Its core rule is:

> Untrusted data may influence an agent, but it must not automatically become execution authority.

BULL sits between a model or agent and sensitive host capabilities such as process execution, filesystems, network egress, credentials, repositories, APIs, and other agents.

## Architecture

```text
Model / agent
     |
     v
untrusted action proposal
     |
     v
trusted canonicalization + provenance
     |
     v
security domain / capability policy
     |
     +---- deny / review
     |
     v
command + resource authorization binding
     |
     v
immutable project snapshot
     |
     v
malware + filesystem integrity gates
     |
     v
Linux namespace + seccomp sandbox
     |
     +---- scoped secret broker
     +---- pinned egress broker
     |
     v
tamper-evident audit trail
```

## Current security controls

- deterministic capability policy
- host-owned identity and provenance context
- canonical filesystem paths with traversal rejection
- capability and parent/child authority checks
- host-issued multi-agent security domains
- shared root-domain behavioral history
- explicit goal-transition records and intent/command/model hashes
- root-domain freeze after hard or coordinated behavioral violations
- command-to-`process.exec` authorization binding
- exact executable-to-authorized-resource binding
- immutable scan-to-execute project snapshots
- filesystem manifest validation
- Linux user, mount, PID, and network namespaces
- `no_new_privs` and seccomp syscall restrictions
- per-execution resource limits
- pre-execution malware scanning
- scoped secret grants with TTL, sandbox binding, revocation, and use limits
- broker operations bound to network or credential authority
- DNS-pinned egress with TLS verification against the original hostname
- tamper-evident hash-chained audit records and trusted runtime events
- optional authenticated external audit anchor
- TLA+ runtime state-machine model
- CI-enforced SANY parsing and TLC invariant checking
- Python regression tests on Python 3.11 and 3.13

## Multi-agent security domains

Every registered agent can receive a host-issued security domain containing a capability ceiling, exact-host egress ceiling, root and parent lineage, spawn depth, provenance, and cryptographic hashes for the model identity, initial prompt/intent, initial command, and domain fingerprint.

Children cannot receive capabilities or egress authority their parent does not hold. Sibling and descendant agents keep distinct domain identities while sharing the root domain's behavioral security history, so splitting a suspicious sequence across several agents does not automatically reset the monitor.

Model-provided identity, provenance, domain, or authority metadata is never accepted as trusted context.

## Execution and broker authorization

An approved filesystem action is not permission to launch an arbitrary command. OS command execution requires `process.exec`, and the executable in `command[0]` must match the executable resource authorized by the action.

Likewise, egress and secret access do not bypass the reference monitor. Domain-mode broker operations require the domain's host-issued authority. Legacy/non-domain broker operations require an authorized `DispatchRequest` and are evaluated by BULL policy before the broker is reached.

## Security boundary

BULL's untrusted-workload boundary is the sandboxed agent process. The host Python process, the BULL trusted computing base, and the Linux kernel remain trusted components.

BULL does **not** claim to protect against a compromised kernel, arbitrary hostile co-tenants with host-level access, hardware attacks, or every possible autonomous-agent failure mode. The formal model proves properties of the modeled state machine; it is not a formal proof of the entire Python/Linux implementation.

## Status

Research prototype with real Linux enforcement and substantial defensive hardening. It is **not yet a production-hardened endpoint-security or multi-tenant isolation product**, and it should not be the sole security control protecting production systems.

## Research direction

BULL explores whether deterministic execution governance, behavioral lineage, small advisory models, formal invariants, and kernel-enforced isolation can constrain much larger autonomous agents while keeping authority decisions model-agnostic and auditable.

```text
control intelligence << generation intelligence
```
