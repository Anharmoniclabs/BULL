# BULL Command Center interpretation guide

The Command Center should explain BULL as an execution-governance boundary, not as a generic AI dashboard.

## Core mental model

A model or agent proposes an action. BULL evaluates the request context, provenance, requested capability, and policy before choosing an execution route.

The four operator-facing routes are:

- **ALLOW** — the authorized path may continue.
- **SANDBOX** — the action may continue only inside constrained execution.
- **ESCALATE** — automatic handling stops and operator review is required.
- **DENY** — the requested action is stopped.

These are policy outcomes, not judgments about whether an agent is "good" or "bad."

## Product hierarchy

The interface should answer these questions in this order:

1. **What is BULL doing right now?**
2. **What request is being evaluated?**
3. **Why did BULL choose this route?**
4. **What enforcement boundary applies?**
5. **What evidence was recorded?**

Avoid making raw implementation details the primary interface.

## Signals are evidence, not authority

Agent Sentinel and artifact scanning are observational inputs. They can add operator context or scrutiny, but must not be presented as identity, attribution, or a replacement for policy and enforcement.

Signal categories are allowed to overlap when the underlying language carries more than one useful observation. For example, "multi-agent" can be counted as both agent-oriented evidence and coordination/swarm evidence. The UI should present those counts as observations, never as mutually exclusive labels or proof of intent.

## Runtime status

Local policy, malware scanning, audit verification, Sentinel, host sandbox evidence, and MicroVM readiness are different layers. A missing KVM device in Codespaces should be presented as a host limitation rather than as failure of the entire BULL product.

## System and brand

The System page should present configuration state in operator language. Approved brand files are implementation assets, not a user-facing file gallery. The interface should use the approved lockup and mark directly and expose only the identity context needed by the operator.

## Presentation mode

Presentation mode should optimize for one clear story: request -> provenance -> capability -> decision -> enforcement -> evidence. It must not imply that a demonstration executed a host-side effect when it did not.
