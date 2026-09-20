# Local MicroVM integration result — 2026-09-20

The one-shot production execution path passed in real QEMU/KVM. This is a
local integration milestone, not production certification or authorization
to release. The audit destination was a disposable authenticated TLS test
collector, not an external production collector.

## Results

| Area | Result | Evidence / limit |
|---|---|---|
| Host regression suite | PASS | 217 collected tests passed, plus 2 subtests; 0 failed, 0 skipped |
| Repository launcher / revised image | PASS | Fresh KVM boots, no private launcher rewriting |
| CPU feature dependency | PASS | No dependency warning; AMD-native SSBD mitigation retained |
| Guest dependencies | PASS | Bash functionality, imports, real offline ClamAV scan, utilities |
| Guest kernel / strict sandbox | PASS | Landlock ABI 9, strict seccomp, no_new_privs, isolated namespaces |
| Authorized production dispatch | PASS | ProductionDispatcher → ProductionRuntime → actual workload, exit 0 |
| Unauthorized harmless request | PASS | DENY, executed=false, no sandbox/workload execution |
| Read-only inputs / runtime | PASS | Supervisor mount checks and sandboxed write-refusal fixture |
| Workload resources / descriptors | PASS | 512 MiB address-space limit; descriptors 0, 1, 2; recorded environment |
| Authenticated control / audit | PASS | Session-bound messages; completion head matched collector storage |
| Timeout | PASS | No successful completion; no remaining workload cgroups or snapshots |
| Cancellation | PASS | Exact QEMU child reaped; missing completion remained interrupted, no replay |
| Missing mandatory strict protection | PASS | ProductionGateFailure before request admission |
| Malformed / missing / replayed control evidence | PASS | Focused host protocol regressions; not extra KVM cases |
| Status-like workload output | PASS | Remained data in the authenticated result payload |
| Revised filesystem consistency | PASS | Read-only e2fsck check |
| External production audit service / deployment identity | BLOCKED | Deployment-specific configuration and real collector validation still required |
| Persistent sessions | DEFERRED | One fresh VM and authority per request |
| Hardware-backed attestation / exhaustive escape coverage | NOT TESTED | Runtime evidence and bounded benign fixtures only |

Five KVM cases were collected; all five passed, none skipped. They are separate
from host pytest results. Guest boot/preflight details are in each boot.log;
actual dispatcher completion, sandbox measurements and audit evidence are in
each report.json. QEMU exit status is recorded separately from workload status.

## Measured allowed run

| Measurement | Milliseconds |
|---|---:|
| QEMU process start → dispatcher-ready guest | 12157.320 |
| Launcher invocation → dispatcher-ready guest | 12282.303 |
| Guest ProductionRuntime / dispatcher initialization | 597.739 |
| Guest dispatch, including admission and scanning | 9165.705 |
| Sandbox setup → trusted pre-exec boundary | 308.901 |
| Pre-exec boundary → process reap | 99.492 |
| Deterministic fixture body | 0.476 |
| Completion audit acknowledgment | 33.714 |
| Result/audit overhead outside dispatch | 34.355 |

These are one-run observations, not latency percentiles. Stages overlap and
must not be summed. VM start uses the actual launcher's QEMU child and host
process start ticks (10 ms resolution). Guest startup and sandbox intervals
use monotonic clocks. The body duration is reported by the actual sandboxed
fixture and corroborated by the trusted completion, not hardware attestation.
The 99.492 ms interval includes interpreter startup, execution and reaping.
No previous host sandbox timing has been relabeled as a MicroVM measurement.

Timing graphs and machine-readable reports are outside Git at:
`/home/al/.local/share/bull/e2e-final-v3-02/`.

## Root causes and permanent corrections

* The literal parser rejected digits in its own DEV_9P key. It now accepts
  digits after the first character while retaining allowlists, duplicate
  rejection and the ban on shell evaluation. The shipped defaults are tested.
* The supported direct-kernel QEMU configuration needs qboot and non-ACPI
  microvm virtio-mmio discovery. The repository implementation now explicitly
  selects that machine contract and verifies deployment-pinned firmware bytes.
* The Intel SSBD CPUID alias lacked its SPEC_CTRL dependency on this AMD/KVM
  host. The explicit AMD-native profile retains the native mitigation and
  uses QEMU enforce to reject unsupported hardware. No warning suppression or
  software-emulation fallback was added.
* The old image lacked production dependencies. A separate pinned Buildroot
  build supplies Bash, ClamAV, Python modules, utilities and libraries. Official
  FreshClam databases were downloaded and verified offline before boot.
* Buildroot ClamAV expects /usr/share/clamav; the payload was under
  /var/lib/clamav. The permanent recipe supplies an immutable alias. The v3
  derivation applies that same alias to a new image and records both hashes.
* A find_library-only check falsely rejected a loadable libseccomp without
  ldconfig. Certification now uses the actual loader, then still requires
  dynamic filter installation and execution. The dynamic probe also locates
  the installed true utility rather than assuming /usr/bin/true.
* Full ClamAV databases failed to load within the old 768 MiB scanner ceiling.
  Measured bounded loading succeeded at 1536 MiB; the guest then independently
  passed scanning. This does not change the separate 512 MiB workload limit.
* Directory storage sizes differed across filesystems and broke snapshot
  content equality. Content hashes now normalize directory storage size;
  file sizes/hashes and original source identity/race checks remain intact.
* The isolated snapshot worker assumed a site-packages installation. It now
  imports from the runtime's own trusted package root under Python -I, without
  using workspace paths or environment import overrides.
* The guest had no real supervised production execution contract. It now
  reads immutable bounded session authority, checks signed deployment gates,
  uses the real dispatcher/runtime, and requires authenticated completion and
  audit acknowledgments. Workload output cannot become a control operation.

No guest NIC was added. Unused SIT tunnel support is omitted from the kernel;
the observed guest/sandbox interfaces were loopback only. R3's down sit0 was
not evidence of an escape. The strict syscall policy remains unchanged at the
observed 170 rules; no broad allowlist expansion was used to fix startup.

## Files changed

| File | Reason |
|---|---|
| .gitignore | Keep firmware, evidence and credentials out of Git |
| microvm/config/defaults.env | Document pinned firmware, CPU profile and dedicated channels |
| microvm/guest/init | Fail-closed preflight, bounded scratch, cgroups and reliable reboot contract |
| microvm/guest/bull-engine | Isolated trusted Python engine entry point |
| microvm/guest/production.fragment | Build production guest dependencies |
| microvm/guest/prepare_build.py | Prepare a separate pinned build with input provenance |
| microvm/guest/finalize_build.py | Validate kernel features and record completed image hashes |
| microvm/guest/derive_database_layout.py | Reproducible new-image database alias correction |
| microvm/guest/DEPENDENCIES.md | Explain dependency and offline-database requirements |
| microvm/integration.py | Real five-case KVM runner and isolated authenticated test collector |
| src/bulldog/microvm.py | Fix actual delegated launcher configuration, boot and port setup |
| src/bulldog/guest_preflight.py | Test guest dependencies before admission |
| src/bulldog/guest_engine.py | One-shot supervised production dispatch and bounded authenticated result |
| src/bulldog/microvm_protocol.py | Bounded ordered authenticated control frames |
| src/bulldog/audit_transport.py | Dedicated verified guest audit bootstrap and acknowledgment gate |
| src/bulldog/production_gate.py | Accept only a live acknowledged trusted relay bootstrap |
| src/bulldog/integrity.py | Include new trusted modules in signed integrity coverage |
| src/bulldog/host_certify.py | Check real library loading and actual utility locations |
| src/bulldog/malware_scanner.py | Size a bounded scanner for the complete official database |
| src/bulldog/snapshot.py | Correct cross-filesystem content hashing and isolated imports |
| src/bulldog/_namespace_launcher.sh | Timestamp trusted sandbox setup completion |
| src/bulldog/namespace_sandbox.py | Validate and propagate sandbox timing evidence |
| src/bulldog/runtime.py | Preserve actual sandbox attestation and timings in results |
| tests/test_microvm.py | Parser, firmware and supported CPU profile regressions |
| tests/test_guest_engine.py | Authority expiry/tampering, relay gate and private ports |
| tests/test_guest_preflight.py | Missing dependencies and functionality failures |
| tests/test_microvm_protocol.py | Framing, replay, sequencing and error/completion separation |
| tests/test_snapshot_content.py | Portable directory hashing without losing file binding |
| docs/MICROVM_R3_FOLLOWUP.md | Retain the earlier investigation as historical context |
| docs/MICROVM_INTEGRATION_REPORT.md | This final evidence and limitations report |

## Reproduce

Run from `/home/al/BULL`. The output directory must not already exist:

```sh
PYTHONPATH=src .venv/bin/python microvm/integration.py \
  --kernel /home/al/.local/share/bull/guest-production-br2026.08-v2/output/images/bzImage \
  --rootfs /home/al/.local/share/bull/guest-production-br2026.08-v3/rootfs.ext4 \
  --firmware /usr/share/qemu/qboot.rom \
  --output /home/al/.local/share/bull/e2e-v3-reproduce-01 \
  --case all --cpu-profile amd-native-ssbd

.venv/bin/python -m pytest -q
```

The runner uses the repository shell launcher unchanged, starts no external
service, and requires working KVM access. The temporary collector is loopback
only; the guest has no network interface for it. No host security setting or
system package installation is required by this completed setup.

## Source and evidence identity

Repository: `/home/al/BULL`; branch: `fix/microvm-guest-integration-r3`.
Base commit: `d218e688a195ed27bff74b08e99459e2b956e088`, with an uncommitted local patch.
The original recorded checkout was clean. Existing work was retained.

All five final cases used source-tree hash
`6316b6ea0e157f6ed6f7eda670fe2a33661b3c851e04f68cf1b40c3c0ecfc545`.
The allowed session was
`8ffa547ad071f844376071f4b372fed9bbb85cfe729a6b58c98cdf73887ca1f2`.
Each report records its own session, guest boot ID, asset hashes and source map.

Evidence: `/home/al/.local/share/bull/e2e-final-v3-02/` contains the five
case reports, boot logs, private collector/relay evidence, regressions.xml,
original-assets.json, timing graph, source.patch and final-source.json.
The latter records the final patch hash, including this documentation.
Image manifests live in `guest-production-br2026.08-v2/manifest.json` and
`guest-production-br2026.08-v3/manifest.json` under the same local BULL data root.

Original R3 logs/script/private override and original v1 build assets were
hash-checked unchanged. The revised images, raw evidence, databases, firmware
and disposable credentials remain outside Git. This document describes the
local validation state before the source change was committed; no release or
deployment action is implied by a source push.

## Remaining limits

Release still requires deployment-owned policy/identity/key provisioning and
validation against the actual external audit collector and supported target
hardware. Disposable fixture keys are not production credentials. Database
freshness needs a controlled image rebuild/update process; there is no
boot-time updater. Full production rollout and adversarial coverage are not
established by these tests.

Persistent VM reuse remains deferred: every request would need authorization
and session binding, resource budgets, expiry/revocation, isolation of state
and credentials, and explicit guest/relay/collector failure behavior. This
implementation does not automatically replay interrupted requests.

The prior /tmp observation only established denial of direct execution under
its tested conditions; it does not establish a blanket ban on interpreted
code. That earlier observation is not presented as a new guest test here.
