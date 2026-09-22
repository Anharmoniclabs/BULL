<p align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="site/assets/brand/bull-primary-dark.svg"><img src="site/assets/brand/bull-primary.svg" width="600" alt="BULL — Blocking Unauthorized Logic Loopholes"></picture></p>

# BULL

**BULL** is an experimental open-source, model-agnostic execution-governance runtime for AI agents.

[The story, implementation and live policy demo](https://anharmoniclabs.github.io/BULL/) · [Shared brand assets](docs/BRAND.md)

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

## Release candidate: 0.2.0rc1

This candidate integrates the runtime hardening from PR #46 and adds a
credentialed human approval gate on production secret/network broker calls.
Contained autonomous computation continues; exact routine HTTPS GET/HEAD URLs
can be listed in signed policy. Every other broker call needs a fresh,
request-bound security-key signature. Missing approval configuration blocks
protected broker calls; existing policy denials are never overridden.

Read [human approval setup and limits](docs/HUMAN_APPROVAL.md),
[claims and required evidence](docs/SECURITY_CLAIMS.md), and
[release status](docs/RELEASE_0.2.0rc1.md). Hardware ceremonies, current-candidate
real KVM and external collector integration remain release validation gates.
This is a reviewable source candidate, not universal protection or certification.

## Current security controls

- signed-policy-controlled, single-use human approval for consequential broker requests
- enrolled security-key signature verification requiring signed presence and verification
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

The [MicroVM integration](microvm/README.md) runs one request through the
repository launcher, a real Linux x86-64/KVM guest, trusted guest supervision,
ProductionDispatcher/ProductionRuntime, and strict namespace/seccomp/Landlock
isolation. Input disks are read-only; authenticated control and audit use
dedicated virtio ports without a guest NIC.

Local validation passed five KVM cases: allowed execution, denied request,
timeout cleanup, cancellation, and missing-protection refusal. The same source
passed 217 regression tests plus two subtests, with no skips. These results
used a disposable authenticated TLS test collector. See the
[integration evidence](docs/MICROVM_INTEGRATION_REPORT.md) and
[release notes](docs/MICROVM_RELEASE_STATUS.md).

The source and local test collector are available for open audit; contributors
do not need an external collector account to inspect or test BULL. Production
operators supply their own policy, keys and audit destination. The host production collector has separate recorded evidence; the joined
current-candidate guest-to-external-collector path and persistent VM reuse remain future work;
macOS/HVF and ARM remain experimental and disabled.

## One-command production host provisioning

BULL includes a fail-closed Linux production provisioner:

```bash
curl -fsSL https://raw.githubusercontent.com/Anharmoniclabs/BULL/main/tools/bull-production-provision.sh -o bull-production-provision.sh
chmod +x bull-production-provision.sh
./bull-production-provision.sh \
  --anchor-url https://YOUR-AUDIT-HOST/v1/checkpoints \
  --anchor-key-file /path/to/owner-only/bull-anchor.key
```

The provisioner creates owner-only deployment state, signed integrity and policy
bundles, strict-seccomp configuration, private snapshot/audit paths, a delegated
cgroup v2 parent and a fresh audit session. It then requires
`bull verify --production`, performs a real authenticated remote-anchor
checkpoint/acknowledgement, and constructs `ProductionRuntime` and
`ProductionDispatcher`. It deliberately rejects localhost/test audit anchors;
the external HTTPS collector and matching master key must already be deployed.
See [production security](docs/PRODUCTION_SECURITY.md),
[audit deployment](microvm/audit/README.md), and the optional
[Cloudflare Workers + D1 audit-anchor package](deploy/cloudflare-audit/README.md).

## Measured benchmark evidence

An operator-run benchmark on September 20, 2026 pinned BULL to commit
`cd461ae05a0925d6bd32381f8ef4da9e99bb2ccb` and repeated 11 selected defensive regression classes three
times each. The result was **33/33 selected runs passed, 0 failures**; the clean
full regression suite also passed in **4.587 seconds** on the recorded host.

See [`docs/BENCHMARK_20260920.md`](docs/BENCHMARK_20260920.md) for measured latency, memory and hot-path data plus interpretation limits. The public engineering page publishes the same graphs and machine-readable summary. Passing this corpus is not an independent security certification.

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
