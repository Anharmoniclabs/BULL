# BULL

**BULL** is an experimental open-source AI execution firewall and defensive runtime for local agents.

The core rule is simple:

> Untrusted data can influence an agent, but it must never automatically become execution authority.

BULL is designed to sit between AI systems and sensitive host capabilities such as the filesystem, shell, network, credentials, subprocesses, repositories, APIs, and other agents.

## Goals

- Treat webpages, files, model outputs, tool results, and agent-to-agent messages as untrusted inputs.
- Track provenance and taint across decisions.
- Enforce deterministic capability boundaries.
- Prevent privilege inheritance beyond a parent agent's authority.
- Detect canary/honeypot access.
- Fail closed when policy cannot be resolved.
- Keep the learned model advisory rather than authoritative.
- Produce tamper-evident audit records for every decision.

## Architecture

```text
External input
     |
     v
Ingress / provenance labeling
     |
     v
Agent proposes action
     |
     v
BULL policy gate
 |       |        |
allow  sandbox   deny
                 |
                 v
             human review
```

## Hardened trust boundary

The model must not be trusted to describe its own authority.

In hardened mode, identity, granted capabilities, parent authority, provenance, canonical filesystem resources, and secret-taint state must come from a trusted host adapter. `ActionRequest.security_context_verified` is therefore a host assertion, not model output. If the trusted boundary has not verified the context, BULL fails closed.

Filesystem actions also require `resolved_resource`, a canonical resource resolved by the host. Project-scoped capabilities are checked against the resolved path rather than the model-provided path string. This is intended to expose path traversal, symlink redirection, and capability-laundering attempts to deterministic policy.

A production deployment should isolate the policy/enforcement process so untrusted agent code cannot directly construct or modify trusted security context.

## Human-auditable adversarial flags

Policy evaluations can include stable security flags with three fields:

```text
severity
machine-readable code
plain-English explanation
```

Examples include:

```text
[CRITICAL] UNVERIFIED_SECURITY_CONTEXT
The action arrived without a host-verified identity, authority, provenance, and resource context.

[CRITICAL] RESOURCE_CAPABILITY_MISMATCH
The real resource does not fit the capability presented for the action.

[HIGH] UNTRUSTED_TO_EXECUTION
Untrusted external content is directly influencing process execution.

[CRITICAL] POSSIBLE_SECRET_EXFILTRATION
Data marked secret-derived is crossing a network or inter-agent boundary.
```

The explanations are for human review. Enforcement is deterministic and does not depend on the wording of these messages.

## Adversarial transitions currently guarded

The hardened policy explicitly checks for:

- self-asserted or unverified security context
- capability use outside the granted authority envelope
- child-agent authority beyond the parent
- project filesystem capabilities resolving outside the project root
- filesystem use without a host-resolved canonical resource
- canary/honeypot access through the resolved path
- sensitive resources reached through the wrong capability
- untrusted external content influencing credential access
- untrusted external content influencing security-control changes
- untrusted external content influencing process execution
- untrusted external content influencing package installation
- untrusted external content influencing agent spawning
- untrusted external content influencing writes into the home environment
- untrusted external content influencing outbound network activity
- secret-derived data crossing network or inter-agent boundaries
- secret-derived state influencing an externally observable side effect
- irreversible actions

## Side-channel scope

BULL can flag a possible side channel when trusted taint tracking says secret-derived state influences an externally observable action. This can catch classes of leakage through network requests, agent messages, output size, externally visible state, or transformed/encoded data when taint is preserved.

This is **not** a proof that all side channels are eliminated. Timing leakage, resource contention, caches, speculative execution, covert channels in allowed protocols, and host-level implementation bugs require isolation and controls below the Python policy layer.

## Current prototype

The prototype contains:

- deterministic policy engine
- capability model
- provenance/taint model
- agent delegation checks
- credential and canary protections
- host-verified security-context gate
- canonical resource containment checks
- human-auditable adversarial flags
- secret-derived exfiltration checks
- advisory small-model interface
- hash-chained audit ledger
- CLI demo
- unit tests

## Status

Research prototype. Not yet a hardened endpoint-security product. Do not rely on it as the sole control protecting production systems.

## Research direction

BULL is intended to test whether a small specialized execution-governance model, paired with deterministic controls, can safely constrain much larger autonomous agents.

Key hypothesis:

```text
control intelligence << generation intelligence
```

The long-term target is a model-agnostic host defense layer for AI agents.
