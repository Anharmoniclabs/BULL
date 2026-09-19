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
tamper-evident + remotely anchored audit trail
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
- `no_new_privs`
- development seccomp compatibility profile
- production default-deny seccomp allowlist profile
- nonce-bound live backend attestation before workload exec
- trusted read-only `/bull_runtime` security bootstrap, separate from `/workspace`
- per-execution resource limits
- pre-execution malware scanning
- scoped secret grants with TTL, sandbox binding, revocation, and use limits
- broker operations bound to network or credential authority
- DNS-pinned egress with TLS verification against the original hostname
- tamper-evident hash-chained audit records and trusted runtime events
- fail-closed authenticated HTTPS remote audit anchoring
- HMAC-authenticated trusted-computing-base integrity manifests
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

## Production profile

Production mode fails closed unless the deployment supplies:

- `BULL_SECCOMP_PROFILE=strict`
- a signed TCB integrity manifest plus an out-of-package signing key
- an authenticated HTTPS remote audit-anchor endpoint
- a successful live namespace/seccomp backend certification

The live attestation is sent over a parent-created nonce-bound pipe that is closed before the untrusted workload begins. It verifies that the sandbox bootstrap is PID 1, `no_new_privs` and the requested seccomp profile are active, only loopback networking is visible, and BULL security code was loaded from the read-only `/bull_runtime` mount rather than the agent workspace.

Generate a signed deployment manifest with:

```bash
export BULL_INTEGRITY_MANIFEST_KEY='use-a-host-secret-manager'
bull manifest --output /etc/bull/integrity.json
```

Then validate a configured host with:

```bash
bull verify --production
```

See [`docs/PRODUCTION_SECURITY.md`](docs/PRODUCTION_SECURITY.md) for the complete trust model and deployment checklist.

For the hardware-virtualized outer boundary under development, see
[`microvm/README.md`](microvm/README.md). The launcher targets Linux x86-64/KVM,
attaches immutable admitted input images by default, disables guest networking,
and requires an explicit trusted engine entrypoint. Persistent production
sessions and real-KVM certification remain unfinished; macOS/HVF and ARM are
experimental and disabled.

## Security boundary

BULL's untrusted-workload boundary is the sandboxed agent process. The host Python process, the BULL trusted computing base, and the Linux kernel remain trusted components.

For mutually hostile tenants, use a separate VM or microVM for each root trust tenant in addition to BULL's internal namespace/seccomp isolation. BULL does **not** claim to protect against a compromised kernel/hypervisor, a malicious host administrator, hardware attacks, or every possible autonomous-agent failure mode. The formal model proves properties of the modeled state machine; it is not a formal proof of the entire Python/Linux implementation.

## Status

BULL now has a **production-oriented hardened profile** with live backend attestation, default-deny syscall filtering, authenticated code-integrity state, remote audit anchoring, and permanent adversarial regression tests. It has **not** undergone an independent third-party security audit and should not be described as vulnerability-free or universally safe.

Repository governance is also part of the boundary: production release use should require GitHub branch protection/rulesets so the regression and formal checks cannot be bypassed.

## Research direction

BULL explores whether deterministic execution governance, behavioral lineage, small advisory models, formal invariants, and kernel-enforced isolation can constrain much larger autonomous agents while keeping authority decisions model-agnostic and auditable.

```text
control intelligence << generation intelligence
```
