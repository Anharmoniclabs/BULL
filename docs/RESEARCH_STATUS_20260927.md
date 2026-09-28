# BULL research qualification checkpoint — 2026-09-27 UTC

Baseline: `ef0cb03` on main. This checkpoint audits the latest assurance/release
changes and runs the main regression suite. It is not a comprehensive independent
security audit, final certification, or an audit of every open branch.

## Corrections in this candidate

1. Downloaded workflow verification records no longer satisfy the attestation
   verification control. Fresh GitHub CLI verification is required against an
   operator-supplied source commit and code-pinned repository/workflow identity.
2. Verification uses the supplied bundles, checks all provenance subjects and
   required boot assets, and binds the expected CycloneDX predicate, rootfs digest
   and supplied SBOM contents. Failure or missing evidence cannot complete release
   assurance. The release workflow invokes these checks before draft creation.
3. Checksum output names cannot escape the release directory. Symlink outputs
   are rejected; atomic replacement avoids truncating hard-linked targets.
   Complete inventory checks reject symlinks and non-regular entries.
4. Assurance profile sections reject empty, duplicate, malformed and wrong-phase
   entries. Failed dynamic certification cannot yield a passing seccomp control;
   malformed Landlock ABI and boolean PID values do not count as valid evidence.
5. Runtime integrity coverage now includes assurance.py, release_evidence.py and
   the packaged assurance registry. Existing signed manifests require trusted
   regeneration, not a verification bypass.

These are reporting, release-validation and integrity improvements. They are not
new proof that arbitrary authorized code, a compromised host, or every prompt
injection is contained.

## Validation

Final candidate on Python 3.12: **533 passed, 21 subtests passed, 4 failed**
(39.09 seconds). Targeted assurance/release suite: **36 passed**. Compilation,
wheel build, website build and diff whitespace checks passed. Baseline:
507 passed, 21 subtests passed, 4 failed. The failures are:

- `test_private_paired_channels`
- `test_bind_private_unix_socket_mode_and_dir`
- `test_accept_authenticated_rejects_foreign_uid`
- `test_bounded_sandbox_output_kills_flooding_workload`

The first three fail because AF_UNIX socket creation is denied by this execution
host. The fourth receives no namespace attestation; a separate `unshare -Ur true`
probe fails writing `/proc/self/uid_map` with Operation not permitted. The tests
and protections were not skipped, weakened or replaced. Consequently the full
source gate is not PASS here. Real KVM and a physical approval device were not
available or exercised.

Finite TLA+ models were checked with the repository-pinned TLC 1.7.4 JAR:

| Model | Generated states | Distinct states | Result |
|---|---:|---:|---|
| BullRuntime | 1,055 | 405 | No invariant error |
| BullSessionAudit | 69 | 57 | No invariant error |
| BullApproval | 218 | 112 | No invariant error |

The first Runtime attempt encountered a JVM SIGBUS. A retry with class-data
sharing and performance shared-memory data disabled completed successfully;
model files and invariants were unchanged. These finite design abstractions
are not proofs of Python, kernel, hypervisor, device, or continuous operation.

Cryptographic-verifier integration tests use a controlled subprocess fixture.
They verify invocation policy and failure handling, not a real signing ceremony.
No genuine release bundle was cryptographically validated in this environment;
`gh` was unavailable. The pinned release workflow must establish that evidence.

## Research and integration map

Open PR inventory was inspected on 2026-09-27 UTC. The descriptions below are
proposed scope from PR metadata, not independently reproduced branch evidence.

| Work | Location | Qualification needed |
|---|---|---|
| Main execution boundary, audit, approval, assurance | main | Clean supported-host CI; current deployment evidence |
| Four-plane lifecycle governance | PR #80 | Review and integrate ahead of production effects; cancellation and cleanup; external checkpoint |
| Egress gateway, proxy tokens, semantic hints | PR #79 | Real guest routing/escape tests; encrypted-traffic limits; durable token lifecycle |
| Live console and investigation workflow | PRs #76 and #77 | Select one operator surface; verify authorization and telemetry through real runtime |
| Alternate command center and redesign | PRs #73 and #74 | Reconcile overlapping interfaces and packaging; preserve truthful unavailable states |
| Copyright/provenance work | PR #71 | Source/license review of actual changes |
| Contained HTTP honeypot | PR #64 | Separate experimental lane; container/socket checks before exposure |

These PRs were not merged by this checkpoint. In particular, lifecycle-governance
research is not yet proof of comprehensive production effect mediation. Do not
present unmerged UI, egress, or lifecycle features as established main behavior.

## Concrete remaining acceptance gates

1. Run the exact candidate on a supported Linux host with local sockets,
   namespaces, strict seccomp/Landlock and delegated cgroups. Preserve every
   failure/skip and bind results to the source commit and image hashes.
2. Run the five real-KVM cases: allowed, denied, timeout, cancellation and missing
   protection. Verify actual side effects, resource cleanup and guest-to-external
   audit receipts, not only reported decisions.
3. Exercise a real enrolled physical approval device: approve, deny, wrong request,
   replay and restart. Synthetic signatures do not establish physical presence.
4. For lifecycle work, enumerate every effect adapter and enforce the governor
   before admission. Race revocation against in-flight effects; record unknown
   outcomes without replay; check lineage cleanup and durable rollback detection.
5. For egress work, test IPv4/IPv6, DNS, redirects, direct IP, TLS/SNI limitations,
   alternate transports and gateway identity isolation in a disposable guest.
   Semantic hints must never create authority or imply encrypted payload inspection.
6. Build a fresh guest release, verify actual signed bundles using the trusted
   expected source SHA, review source/license materials, then repeat KVM checks.
7. Obtain independent review before higher-risk deployment. Historical paper
   results remain tied to their original qualification cutoff; no new empirical
   claims should be inserted into those published results without new evidence.

Research can be checkpointed reproducibly; it cannot honestly be declared
universally finalized. The next promotion decision requires the gates above.
