# MicroVM release notes and status

## One-shot KVM integration milestone — 2026-09-20

BULL now executes an authorized harmless workload through the repository
launcher, real QEMU/KVM guest, trusted guest supervision,
ProductionDispatcher/ProductionRuntime, and strict namespace, seccomp and
Landlock isolation. Dedicated authenticated virtio channels carry control,
results and audit acknowledgments without a guest NIC.

This experimental OSS milestone is available for public inspection and local
reproduction. Merging or distributing its source does not require contributors
to own a production collector or provide credentials. Runtime operators supply
their own production policy, keys and audit destination. The local suite used
a disposable authenticated TLS collector and validated no external service.

### Included changes

- Correct literal configuration parsing for documented keys containing digits.
- Validate pinned qboot firmware and the supported microvm machine contract.
- Support the verified AMD-native SSBD correction with enforced hardware support.
- Build versioned guest dependencies including Bash and verified offline ClamAV
  databases; check actual functionality before admitting workloads.
- Provision bounded private scratch and cgroup v2 resources inside the guest.
- Implement one-shot session authority, authenticated control/audit, actual
  production dispatch, bounded output and explicit completion evidence.
- Preserve full argv authorization, signed policy/integrity, malware scanning,
  strict sandbox setup and runtime transition verification.
- Correct cross-filesystem snapshot hashing and isolated worker package imports.
- Verify cleanup after timeout/cancellation and reject invalid completion evidence.

### Validation

| Scope | Recorded result |
|---|---|
| Host regressions | 217 passed plus 2 subtests; 0 failed, 0 skipped |
| Real local KVM | 5 passed; 0 failed, 0 skipped |
| Guest cases | Allowed, denied, timeout, cancellation, missing strict protection |
| Guest sandbox | Landlock ABI 9, strict seccomp, no_new_privs, loopback only |
| Audit destination | Disposable authenticated local TLS test collector |
| Original assets/evidence | Hash-verified unchanged; excluded from Git |

The [integration report](MICROVM_INTEGRATION_REPORT.md) records source and asset
identities, stage timings and limitations. The [MicroVM README](../microvm/README.md)
provides portable test commands. The recorded KVM run predates documentation-only
follow-up commits; it does not claim that hosted CI booted KVM for those edits.

### Merge and distribution

Use the repository's pull-request process and required checks, signature rules
and conversation resolution. Publish source and documentation while keeping
images, firmware, databases, private configuration, credentials and raw local
evidence outside Git. Do not bypass branch protection to merge this milestone.

These results do not establish production certification, an independent audit,
complete containment or exhaustive adversarial coverage. BULL remains open
for independent audit and contribution.

### Operator requirements and future work

- Production use requires deployment-owned signed policy and integrity authority,
  session keys, trusted firmware/images and an authenticated audit collector.
  Validate acknowledgments and failure behavior for the actual destination.
- Maintain offline signature database freshness through controlled image updates.
- Validate each supported hardware/QEMU/kernel combination.
- Hardware-backed attestation and independent security assessment remain untested.
- Persistent VM reuse is deferred: every request needs authorization and session
  binding, limits, expiry/revocation, credential/state separation and defined
  failure behavior. Interrupted work must not be replayed automatically.
- Writable workspace promotion and artifact export remain future scope; this
  milestone uses read-only input workspaces.
- ARM and macOS/HVF remain experimental and disabled. There is no software fallback.
- A hosted required KVM CI job remains future work. Host-only CI does not
  substitute for the locally demonstrated real guest execution.
