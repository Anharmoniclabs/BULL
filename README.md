# BULL

**BULL** is an experimental open-source, model-agnostic execution-governance runtime for AI agents.

The core rule is simple:

> Untrusted data can influence an agent, but it must never automatically become execution authority.

BULL sits between AI systems and sensitive host capabilities such as the filesystem, shell, network, credentials, subprocesses, repositories, APIs, and other agents.

## Goals

- Treat webpages, files, model outputs, tool results, and agent-to-agent messages as untrusted inputs.
- Track provenance and taint across decisions.
- Enforce deterministic capability boundaries.
- Prevent privilege inheritance beyond a parent agent's authority.
- Isolate agents in kernel namespaces with seccomp and resource limits.
- Bind multi-agent identities to trusted host context rather than model-controlled metadata.
- Fail closed when policy, malware scanning, integrity, or formal transition checks cannot be resolved.
- Keep learned models advisory rather than authoritative.
- Produce tamper-evident audit records for decisions, agent lineage, and scoped broker activity.

## Architecture

```text
Any model / agent
      |
      v
Untrusted action proposal
      |
      v
Trusted canonicalization + provenance
      |
      v
Capability / session / lineage policy
      |
      +---- deny / review
      |
      v
Immutable project snapshot
      |
      v
Malware + integrity gates
      |
      v
Kernel namespace + seccomp sandbox
      |
      +---- scoped secret broker
      +---- pinned egress broker
      |
      v
Audited workload
```

## Multi-agent isolation

BULL can register each agent in an immutable **execution envelope** containing:

- host-assigned agent identity
- model identity
- initial model intent
- bootstrap command
- parent agent identity
- granted capability set
- unique sandbox identity
- security-context identity
- cryptographic intent, command, and lineage hashes

A child agent cannot receive capabilities its parent does not possess, and creating a child requires the parent to hold `agent.spawn`. Model-provided identity, provenance, sandbox, and lineage fields are ignored during trusted canonicalization.

Each sandbox execution receives only non-secret identity hashes/IDs through its environment. Raw secrets remain brokered from the host. In multi-agent mode, unscoped secret and egress dispatcher calls are disabled; broker activity is tied to the registered agent and can enter the same tamper-evident audit chain.

## Current runtime controls

- deterministic capability policy
- trusted action canonicalization
- provenance and session-drift controls
- parent/child authority checks
- immutable scan-to-execute snapshots
- filesystem manifest validation
- Linux user/mount/PID/network namespaces
- `no_new_privs` and seccomp syscall restrictions
- per-execution resource limits
- pre-execution malware scanning
- scoped secret broker with TTL and use limits
- DNS-pinned egress broker with TLS hostname verification
- tamper-evident hash-chained audit ledger
- optional authenticated external audit anchor
- TLA+ runtime state-machine model
- CI-enforced SANY parsing and TLC invariant checking
- live Python transition-conformance checks
- multi-agent intent/command/lineage audit binding

## Security boundaries

BULL's untrusted workload boundary is the sandboxed agent process. The Python host process, kernel, and BULL trusted computing base remain trusted components. BULL does **not** claim to solve arbitrary hostile co-tenant processes, a compromised kernel, or universal autonomous-agent safety.

The formal model proves properties of the modeled state machine; it is not a proof of the entire Python/Linux implementation. CI continuously checks the model and regression tests continuously exercise implementation-level boundaries.

## Status

Research prototype. The runtime now contains real Linux enforcement and substantial defensive hardening, but it is not yet a production-hardened endpoint-security product. Do not rely on it as the sole control protecting production systems.

## Research direction

BULL tests whether deterministic execution governance, small advisory models, formal invariants, and kernel-enforced isolation can constrain much larger autonomous agents while keeping authority decisions auditable and model-agnostic.

```text
control intelligence << generation intelligence
```
