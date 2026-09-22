# BULL production security boundary

BULL is an execution-governance runtime for AI agents. Production mode is a fail-closed profile, not a claim that arbitrary AI behavior or a compromised host can be made universally safe.

## Trusted computing base

Production assumes these components are trusted:

- the Linux kernel and host administrator
- the BULL host process and installed BULL package
- the host-issued `SecurityDomainRegistry` state
- the secret and egress broker host processes
- the deployment integrity-manifest HMAC key
- the remote audit-anchor HMAC key and endpoint

Untrusted components include model output, prompts from external sources, project/workspace content, agent-created child processes, downloaded files, and workload code executed inside the sandbox.

## Production gates

`ProductionRuntime` and `ProductionDispatcher` require the deployment controls
below. The legacy `production_mode=True` Boolean cannot create a production boundary.

- `BULL_SECCOMP_PROFILE=strict`
- `BULL_INTEGRITY_MANIFEST=/absolute/path/to/signed-manifest.json`
- `BULL_INTEGRITY_MANIFEST_KEY=<deployment secret>`
- `BULL_REMOTE_AUDIT_ANCHOR_URL=https://...`
- `BULL_REMOTE_AUDIT_ANCHOR_KEY=<deployment secret>`
- `BULL_AUDIT_SESSION_ID=<fresh host-issued 64-character hex ID>`
- signed policy, private snapshot scratch, durable audit ledger, and delegated
  cgroup v2 configuration as validated by `production_gate.py`

The production gate performs a dynamic backend certification, not only binary/path presence checks. The real namespace sandbox must start successfully and return a nonce-bound attestation proving:

- PID namespace bootstrap is PID 1
- `no_new_privs` is active
- seccomp is active
- the expected seccomp profile is active
- no non-loopback network interface is visible
- security bootstrap code came from the read-only `/bull_runtime` mount

## Sandbox security bootstrap

The workload project is mounted at `/workspace`. BULL security code is never imported from that path. The installed BULL package is mounted separately, read-only, at `/bull_runtime`; seccomp is loaded only from that trusted mount.

The sandbox runtime uses a parent-created pipe carrying an unpredictable nonce. After `no_new_privs` and seccomp are installed, the bootstrap writes exactly one attestation to that pipe and closes the descriptor before `exec`. The untrusted workload never receives the attestation descriptor and cannot issue a replacement attestation.

## Seccomp profiles

`compat` is for development and backwards compatibility. It is default-ALLOW with explicit denial of high-risk kernel-control syscalls.

`strict` is the production profile. It is default-EPERM and allows an explicit userland syscall baseline. Kernel-control surfaces such as mount, namespace manipulation, ptrace, BPF, kernel module loading, userfaultfd, io_uring setup, process-vm access, and similar primitives are absent from the allowlist.

A workload that needs a syscall outside the strict profile should receive a reviewed profile change; production should not silently fall back to `compat`.

## Integrity manifest

The production manifest contains SHA-256 hashes for the BULL trusted computing base, including the namespace launcher. Production additionally requires an HMAC-SHA256 signature using a key stored outside the package/repository.

This closes the previous weakness where an attacker able to replace both package files and an unsigned manifest could make tampered code appear internally consistent.

## Remote audit anchoring

The production HTTPS transport posts only:

- monotonic sequence number
- hash-chain head
- HMAC-SHA256 authentication tag
- session ID and previous checkpoint hash

No prompt, secret, or workload payload is sent to the anchor by this mechanism.

A local remote-checkpoint advances only after an authenticated acknowledgement
binding the session, sequence, and head hash. The legacy URL-only ledger API
does not satisfy production checks. If delivery fails, the checkpoint remains
behind and subsequent verification/appends fail closed. Explicit recovery
retries the checkpoint without replaying any command. The reference SQLite
service commits before acknowledging. See [deployment and recovery](../microvm/audit/README.md).

## Multi-agent isolation

Each agent is assigned a host-generated security domain. Children may only inherit subsets of parent capabilities and approved egress hosts. Siblings keep distinct domain identities but share root behavioral history, preventing an agent tree from resetting behavioral controls simply by moving an action to another child.

Secrets are TTL/use-limited and can be bound to a specific domain. Egress is the intersection of domain host authority and broker allowlist policy. Serious hard policy or cross-agent behavioral violations can freeze the entire root domain.

## Execution binding

Every OS command launch requires `process.exec`. The canonical executable authorized by policy must equal `command[0]`; a read/write/network capability cannot be used as a generic ticket to run an unrelated executable.

Legacy egress and secret broker access must carry a policy-authorized `DispatchRequest`. Domain mode derives broker authority from the trusted host-issued domain instead of model-controlled fields.

## Filesystem admission

Project content is validated before snapshot, copied to an isolated snapshot, validated again, scanned, hash-bound after scanning, and only that admitted snapshot is mounted for execution. Symlinks, hardlink surprises, special files, and source mutation during snapshotting fail closed.

## Remaining trust limits

Even with all production gates active, BULL does **not** claim protection from:

- a compromised or malicious kernel/hypervisor
- a hostile host administrator
- side channels between workloads that share the same physical kernel
- vulnerabilities in allowed kernel syscalls or the Linux namespace implementation
- malicious behavior that remains entirely inside explicitly granted authority
- correctness bugs that are absent from the formal abstraction and test corpus

For mutually hostile tenants, put each BULL root security domain in a separate VM or microVM in addition to BULL's internal namespace/seccomp controls.

## Deployment checklist

1. Run BULL inside a dedicated VM or microVM for each trust tenant.
2. Run with `BULL_SECCOMP_PROFILE=strict`.
3. Generate and sign the integrity manifest outside the deployed package.
4. Store integrity and audit-anchor keys in the host secret manager, not the project workspace.
5. Use a dedicated HTTPS remote audit-anchor endpoint.
6. Keep broker Unix sockets outside any agent-writable mount.
7. Do not expose the Docker/container daemon socket inside agent sandboxes.
8. Require the Python security regression and TLA+ workflows before merging to `main`.
9. Enable GitHub branch protection/rulesets so those checks cannot be bypassed.
10. Re-run dynamic host certification after kernel, container-host, or BULL upgrades.

## Repository protection

Main now has an active solo-maintainer ruleset requiring pull requests,
verified signatures, resolved conversations, the Python security regression
jobs, and TLA+ checks, with force pushes and deletion blocked. No second
reviewer is required. The signed audit PR demonstrated a protected merge.
Dedicated MicroVM host regression checks are added after their workflow lands;
real KVM integration remains a release prerequisite. See the
[rollout instructions](../microvm/governance/README.md) and
[remaining release work](MICROVM_RELEASE_STATUS.md).

## Consequential broker approval in 0.2.0rc1

ProductionDispatcher now adds credentialed approval after existing policy
allows a secret or network operation. Signed routine GET/HEAD URLs are the only
network exception. Without signed `human_approval` configuration these broker
operations fail closed. Read-only contained execution remains available.
See [configuration and ceremony](HUMAN_APPROVAL.md) and
[claims and limits](SECURITY_CLAIMS.md). `bull verify --production` certifies its
existing host prerequisites only; it does not claim a hardware approval ceremony,
complete adapter coverage or current guest-to-external-collector validation.
