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
