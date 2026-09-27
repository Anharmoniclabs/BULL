# BULL integration candidate and live KVM status — 2026-09-27 UTC

Candidate based on hardening PR #81 (`f6a0cb935a3c89173a2d074cc00e53f8f5bc90e1`)
plus selected source from command-console PR #76, egress PR #79 and lifecycle
PR #80. The alternate UI PR #73 remains separate: one packaged `bull console`
operator surface is chosen here. PR #77 has no changed files as inspected.
The branches were reconciled by file and then changed; their earlier test counts
are historical and cannot qualify this candidate.

The combined candidate test run passed 643 tests and 21 subtests. Four tests
could not pass in this restricted runner: three private Unix-socket cases were
denied by the host and one sandbox-output case could not obtain namespace
attestation. The lifecycle lab's 56 tests and the site suite's 20 tests passed.
These results establish local regression coverage, not live guest qualification.

| Area | Candidate state | Specific remaining proof |
|---|---|---|
| Lifecycle | Packaged governor and one exact-command host bridge; one-use admission precedes ProductionDispatcher | Mediate broker effects and remaining host adapters; bind provenance to real intake; physical approval and independent rollback anchor |
| Egress | Gateway policy validation, bounded parsing, fail-closed opaque TLS rules, NAT redirect plus filter-drop recipe, no ambient credential injection | Apply rules in disposable guest; test IPv4/IPv6, raw IP, DNS variants, alternate ports, restarts, gateway UID isolation, redirect and cleanup |
| UI | Single packaged `bull console` with read-only integration qualification cards | Test a deployed console with actual source-bound KVM and gateway reports; refine investigation interaction without simulated claims |
| Real KVM | **BLOCKED in this runner** | Five cases on a KVM-capable Linux x86-64 host with this exact clean candidate and verified guest assets |

The observed `tools.deployment_check.probe_kvm()` result here was
`{"status":"BLOCKED","exception":"FileNotFoundError","reason":"[Errno 2] No such file or directory: '/dev/kvm'"}`.
`qemu-system-x86_64` and `nft` are also absent. Neither software emulation nor
older `guest-2026-09-22` results count as current candidate KVM proof. The
MicroVM CI workflow tests host launch and fixtures and says explicitly that it
does not boot a KVM guest.

On a trusted host with KVM and verified release assets, create the local
`assets-local.json` manifest as in `docs/CODESPACES_VM_AND_KEY_CHECKS.md`, then
run this candidate from a **clean checkout**:

```bash
python3 tools/deployment_check.py \
  --output /private/new-bull-evidence-dir \
  --assets /private/guest-release/assets-local.json
```

The tool tests the KVM device API, checks asset SHA-256 values, runs allowed,
denied, timeout, cancel and missing-protection cases, and checks each case's
source revision and asset digests. Check the `current_candidate_kvm` gate and
all five `kvm/*/report.json` files. A local TLS fixture collector is only a
fixture; configure a separate external collector for that additional gate.
Do not promote if any gate is FAIL, BLOCKED or skipped. Keep private signing
keys, raw ledger data and runtime state out of the pull request. Record the
actual source/image identities and the guest routing probes before describing
this candidate as production-qualified.

Unit tests for the bridge use a controlled ProductionDispatcher fixture; they
prove ordering, binding and replay rejection, not host isolation. Gateway
socket/TLS tests do not test nftables. The new code does not establish universal
prompt-injection prevention, compromised-host resistance, or a persistent
agent-wide execution boundary.
