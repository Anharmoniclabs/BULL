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

Operator-provided Codespaces transcript subsequently showed all five live
one-shot cases PASS on clean commit `6a270237202e350db1435c6f171b644efe2299c0`.
The selected release image hashes and source-tree digest are recorded in PR #82.
The private per-case reports were checked by the runner for matching revision
and image hashes, but have not been independently inspected here. The current
head after adding console evidence intake and the isolated egress lab is a new
revision and requires a new five-case run for a current-head claim.

The console can consume an operator-selected private run directory:

```bash
PYTHONPATH=src python3 -m bulldog.cli console --qualification-dir /tmp/bull-kvm-EXAMPLE \
  --host 127.0.0.1 --port 11511 --no-auto-scan --no-dynamic-attestation
```

Its integration card reports PASS only when all five private case reports and
the summary agree with the setup report and the console's source revision;
otherwise it reports STALE or INVALID without exposing report contents.

For a disposable routing probe in a separate Linux network namespace, run
`python3 tools/egress_namespace_lab.py --install-deps`. The script refuses the
host network namespace and never installs host nftables rules. It substitutes
the existing unprivileged `nobody` UID for the `bullgw` service UID in a
temporary copy of the recipe, checks one allowed and denied HTTP redirect,
denied DNS, off-loopback alternate TCP drop (with a lab-only nft counter) and
gateway-down behavior. Other loopback services are explicitly permitted. This is a scoped
IPv4 namespace probe; it cannot certify guest deployment, IPv6, service
restart, real upstream egress or exact bullgw identity. If Codespaces denies
network namespace creation, report BLOCKED and run the recipe in a disposable
guest/host that supports it.

On a trusted host with KVM and verified release assets, create the local
`assets-local.json` manifest as in `docs/CODESPACES_VM_AND_KEY_CHECKS.md`, then
run this candidate from a **clean checkout**:

For the five-case guest fixture alone, use the one-command helper from a clean
checkout of this integration PR (including its helper commit):

```bash
python3 tools/run_codespace_kvm.py --install-deps
```

It first probes the actual KVM device/API. If Codespaces denies it, the helper
writes a private `setup-report.json` under `/tmp/bull-kvm-*` and stops before
downloading images or changing packages. With KVM, it downloads the pinned guest
release through `gh`, verifies the needed release file hashes and local image
manifest, installs missing Debian VM tools only with `--install-deps`, then runs
all five cases and checks their source/image identities. An existing verified
manifest can be supplied with `--assets /absolute/assets-local.json`. The
private run directory contains disposable credentials; share reviewed reports,
not the whole directory. This fixture does not verify live egress nftables rules.

### Current offline guest boundary

The pinned guest is intentionally launched with QEMU `-net none`; its published
kernel recipe has no virtio network device or IPv6 support. In a clean KVM
operator shell, use the verified local image manifest to run the separate
offline fixture:

```bash
python3 tools/run_codespace_kvm.py --offline-egress \
  --assets /absolute/path/to/assets-local.json
```

This case checks the observed QEMU child command line and runs an IPv4/IPv6
outbound probe in the actual governed guest workload. It requires only loopback
to be visible and both connections to fail. The private case report and setup
report remain source and image bound. To display the sanitized result, start
`bull console --offline-egress-dir /tmp/bull-kvm-NEW` with that run's directory.
The console displays an **offline guest boundary** card separately from the
**egress enforcement** card. A passing offline case is evidence that this
specific guest workload had no network path; it does not test a deployed
`bullgw` service or authorize enabling a guest network adapter. A networked
guest requires a distinct image, boot recipe and in-guest gateway qualification.

For the broader production qualification gate, run:

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
