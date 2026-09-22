# Candidate validation — 2026-09-22

Base: `aa169ced481cbe1c0944c5c3d8516a48ffd46704`. Changes are the 0.2.0rc1
candidate patch; this is not a result for unchanged main. Local environment:
Python 3.12.14, Linux 6.18.44 x86-64. Hosted 3.11/3.13 CI is separate evidence.

- The first candidate run completed all tests with no skips; it exposed an
  obsolete documentation expectation and the same four environment failures as
  the pre-feature hardening baseline. The wording assertion was updated to match
  the documented distinction between host external-collector evidence and the
  still-required joined guest/external-collector run.
- Final local regression: **303 passed, 4 failed, 6 subtests passed, 0 skipped**
  in 5.07 seconds. All four remaining failures are listed below.
- New signature/state tests use real OpenSSH verification of synthetic SK
  credentials. They do not establish genuine hardware or a physical human.
- Both existing TLA+ models and the new approval model parsed and model-checked
  successfully with pinned tla2tools 1.7.4. Approval: 218 states generated,
  112 distinct states, depth 6. This is a finite design abstraction.
- Wheel packaging and static site build succeeded.

Four local environment gates remain failures, not skipped successes:

| Test | Observed blocker |
|---|---|
| `test_private_paired_channels` | AF_UNIX socket creation: EPERM |
| `test_bind_private_unix_socket_mode_and_dir` | AF_UNIX socket creation: EPERM |
| `test_accept_authenticated_rejects_foreign_uid` | AF_UNIX socket creation: EPERM |
| `test_bounded_sandbox_output_kills_flooding_workload` | Namespace sandbox did not produce required backend attestation |

No security prerequisite was disabled to make these tests green. `/dev/kvm` is
not available here. No deployment keys, physical authenticator, guest images or
production collector were supplied to this workspace. Therefore current-candidate
production host, KVM, physical ceremony, and external end-to-end claims remain
unverified. See release notes for the promotion gates.

Use `tools/release_check.py` to obtain exact current counts and a content-identified
machine-readable report on the intended host. The report retains full failures
and marks `certified: false`; no universal malicious-AI protection is claimed.

## Hosted candidate checks

GitHub Actions completed on candidate `377ef3c4b9e8ac3a5d2777888711aecdf8018e2d`:

- Python 3.11: **307 passed, 6 subtests passed**, no failed/skipped tests (4.36 s).
- Python 3.13: **307 passed, 6 subtests passed**, no failed/skipped tests (3.90 s).
- Required security workflow: https://github.com/Anharmoniclabs/BULL/actions/runs/35732645334
- All three formal models: https://github.com/Anharmoniclabs/BULL/actions/runs/35732645399
- MicroVM host regressions: https://github.com/Anharmoniclabs/BULL/actions/runs/35732645118
- Publication verification/build: https://github.com/Anharmoniclabs/BULL/actions/runs/35732646554

These hosted passes resolve the source-test uncertainty from the four local
environment failures. They do not replace real KVM, physical device, or external
collector integration evidence. The local failures above remain part of the record.

## Codespaces permission regression and fixture correction

The operator's Codespaces run of main `b5059c33660d63d025f03060dd933f88aad8de25`
used Python 3.14.2 and reported **302 passed, 5 failed, 6 subtests passed, 0 skipped**.
All three formal models, packaging, and the website build passed. Source validation
correctly remained failed. The checkout's `microvm/config/defaults.env` had mode
`0666`; failures also occurred at permission checks on freshly created authority,
firmware, and diagnostic configuration fixtures.

The same five failures were reproduced locally on Python 3.12 by using umask
`000` and a mode-`0666` source template. The tests relied on ambient filesystem
permissions. This reproduction does not establish which Codespaces setting
produced those permissions.

The correction provisions valid test authority, firmware, and configuration files
with explicit mode `0600`. The shipped-template parsing test first copies the
template into a private deployment fixture, reflecting the production setup
contract. Nine additional cases separately verify rejection of group-writable,
world-writable, and mode-`0666` files. Configuration syntax tests now assert their
specific rejection reasons so an earlier permission failure cannot mask a parser
regression. Runtime permission enforcement is unchanged.

The required MicroVM host CI jobs now exercise the two affected test modules with
umask `000` and a writable source template. Local correction results:

- Permissive-permissions run: **41 passed, 1 failed**. The remaining failure is
  the already documented AF_UNIX restriction on `test_private_paired_channels`.
- Full suite: **312 passed, 4 failed, 6 subtests passed, 0 skipped**. The four
  remaining failures are the same local environment blockers listed above.

Hosted CI for the correction and a fresh Codespaces release-check report provide
separate evidence. These fixture changes do not qualify hardware or deployment
security; those promotion gates still apply.

## Deployment runner wiring

The operator subsequently reported all source gates passing in Codespaces on
`b0c702274f14379fad38c57a4f8d88022365627b`: Python 3.14.2, clean checkout, 322 JUnit
records including subtests, zero failures/errors/skips. This is operator-provided
source evidence; the deployment gates in that report remained NOT_RUN.

The deployment runner adds actual environment probes and connects existing
hardware/KVM checks to one command. The KVM path now supports an external
collector with a completion-bound authenticated receipt and separate guest/host
keys. Nine runner regressions cover device probing, cleanup, pinned-asset
integrity, private key handling, skipped evidence, and a real loopback TLS relay.

Local wiring validation: **321 passed, 4 failed, 6 subtests passed**. The four
failures are the same local AF_UNIX/backend restrictions documented above. The
deployment command itself completed and retained those restrictions, missing
KVM/assets/credentials and the dirty development tree as non-passing evidence.
Physical device and real guest/external tests still require an operator run with
the actual prerequisites. CI exercises a clean checkout and asserts that missing
deployment inputs remain BLOCKED rather than being reported as certification.

## Portable deployment and public guest preparation

The portable provisioner replaces personal paths and shared authority with a new
private state directory per installation. Independent policy, integrity and
collector keys and audit identities are generated locally. Existing authority is
never rotated on rerun. The deployment checker verifies that selected state and
does not inherit another installation's `BULL_*` credentials.

Twenty-two provisioning regressions cover independent installations, actual
cross-key checkpoint rejection, cross-policy/manifest rejection, private file
permissions, preservation of exact imported secret bytes, stable authority,
approval enrollment requirements and rejection before downstream checks.
Seven public recipe regressions cover unverified databases, changed inputs,
missing package requirements, changed source identity and invalid preparation.

The final local suite reports **350 passed, 4 failed, 6 subtests passed**. The four
failures are the previously recorded AF_UNIX/namespace restrictions of this
execution environment. A documentation contract assertion was corrected to keep
the compatibility wrapper documented; no runtime security gate was relaxed.

Real configuration of pinned Buildroot `d5180309b1b66ef3b8eaccca70ad69be8e0729a1`
completed with the mandatory packages and download hash enforcement selected.
The kernel archive's SHA-256 matched its pinned official checksum. CI additionally
resolves the actual Linux Kconfig and exercises administrator cgroup delegation
followed by unprivileged process placement. Local cgroup mutation is unavailable
because this execution environment mounts cgroup read-only.

The new public recipe has **not** completed image compilation, VM boot, physical
approval, independent review or a two-build byte comparison in this validation.
`CONFIGURED_NOT_BUILT`, `BUILT_NOT_BOOT_TESTED`, BLOCKED deployment gates and
`certified: false` remain explicit. Hosted workflow results qualify only their
reported checks, not the missing deployment evidence.

Hosted validation on candidate `1608c3ab8423259fc3ad7debd53ad646469b2a38`:

- Python 3.11 and 3.13 each report **354 passed, 6 subtests passed**, zero test
  failures or skips. Both jobs also passed real cgroup limit readback and
  unprivileged child placement, and the isolated deployment smoke check:
  [security regression](https://github.com/Anharmoniclabs/BULL/actions/runs/35748614699).
- Public Buildroot configuration and actual Linux 7.1.13 Kconfig resolution passed:
  [public recipe configuration](https://github.com/Anharmoniclabs/BULL/actions/runs/35748615035).
- All three bounded formal models passed:
  [formal invariants](https://github.com/Anharmoniclabs/BULL/actions/runs/35748614703).
- Host-side MicroVM regressions passed on both Python versions:
  [MicroVM regressions](https://github.com/Anharmoniclabs/BULL/actions/runs/35748614696).
- Static publication verification and build passed:
  [publication checks](https://github.com/Anharmoniclabs/BULL/actions/runs/35748614790).

These hosted results resolve the four local source-test restrictions for that
candidate. They do not supply the missing full-image, hardware or external
collector/guest evidence listed above.
