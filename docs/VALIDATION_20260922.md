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

## CachyOS production validation follow-up

This section is new agent-executed evidence, separate from the historical
operator results above. Origin/main was fetched and remained
`974eb17081e3374e99ecd35f9ebb3ef6121beefa`. The original checkout was clean and
left unchanged; work used a separate worktree with umask 022.

The operator's prior `/home/al/bull-evidence/bull-local.tqb90x/checks` reports and
logs were inspected. They recorded 364 JUnit records, strict host checks, 34
synthetic approval tests, disposable TLS, verified images, and five local VM
cases passing. Production configuration, external host/guest collection, and
physical approval were BLOCKED. These are prior results, not reruns.

### New clean-candidate results

Candidate `67d452d8d740e36aa72d61136ca954ea526ac9b7`, tracked-content SHA-256
`b5ec916ff50b872ff9df67b91d8c7040b9880676f874238a5479b42dcd9b4f57`, passed:

| Requirement | Executed check and outcome |
|---|---|
| Source, authorization, narrow grants, integrity/audit failures | Release suite: 371 JUnit records, zero failures/errors/skips |
| Approval side effects | 38 synthetic protocol tests; missing, wrong, expired, reused and changed approvals are rejected; callback fixtures observe no unauthorized effects |
| Formal abstraction | All three models parsed and checked: Runtime 405 distinct states, SessionAudit 57, Approval 112 |
| Packaging and site | Wheel and static site build PASS |
| Portable production inputs | Private new validation deployment, signed policy/manifest verification, strict host and production configuration PASS |
| Rerun authority preservation | Second init refused; existing private file bytes unchanged |
| Real cgroup enforcement | UID 1000 child placement and limit readback; CPU throttling, memory OOM-kill and pids rejection counters; cancellation/timeout scope removal PASS |
| Audit transport | Disposable local TLS/outage test PASS; external host authenticated receipt PASS |
| Current guest and external collector | Allowed, denied, timeout, cancel, missing-protection: 5/5 PASS; exact completion receipt correlation PASS |
| Source identity | Clean before/after and unchanged source PASS |
| Physical approval | BLOCKED: compatible enrolled authenticator plus operator interaction still required |

Full private evidence is retained at
`/home/al/bull-evidence/production-20260922/candidate-checks`. The checker exited
1 because hardware approval was BLOCKED, not because any automated gate failed.
No skipped check was counted as passed. A final run after the follow-up's last
edits is stored alongside it under `final-checks`; its `source.json` and source
report identify the final commit and content digest. The PR records that final
run's outcome. These reports are private; only this reviewed summary is public.

### Environment, assets and commands

Host: CachyOS Linux 7.2.6-1-cachyos x86-64, glibc 2.44, Python 3.14.7,
pytest 9.1.1, cryptography 46.0.7, setuptools 84.0.0, QEMU 11.1.1,
e2fsprogs 1.47.4, OpenSSL 3.6.4, OpenSSH 10.5p1, systemd 261.3,
OpenJDK 17.0.19. PATH included `/usr/sbin` and `/sbin`; QEMU, OpenSSL,
mkfs.ext4, debugfs, e2fsck and resize2fs were checked before running.

Existing images were reused after SHA-256 verification, without rebuilding or
large downloads:

| Input | SHA-256 |
|---|---|
| bzImage | `66bcc80464908d0bbdb5e854eba369d1fa509f71656d9f8baa32073349315daa` |
| rootfs.ext4 | `5a99e8eb82d3acba04efaf23c94c2fad2e01a14b09e9c3b2fe6e07326ccc665b` |
| qboot.rom | `14a5f6679d16477c44ed947a50dae3c772dc77107715c09ab3ac3f5ef2763c98` |
| tla2tools 1.7.4 | `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88` |

The downloaded assets manifest contained CI-runner paths. A new private local
manifest retained the expected hashes and named the actual local files. The
original manifest was not changed. Public guest code is now staged as readable
0644 files and 0755 directories/launchers independently of private evidence
umask; deployment secrets remain private. A regression verifies that staging
does not change original source permissions.

The exact agent run used the existing test interpreter and these commands
from `/home/al/Projects/BULL-production-validation`:

```bash
PYTHONPATH=src /home/al/bull-local-tests.iI2sro/.venv/bin/python -m pytest -q \
  tests/test_deployment_setup.py tests/test_human_approval.py

systemd-run --user --wait --pipe --collect --unit=bull-validation-20260922 \
  --property='Delegate=cpu memory pids' --property=DelegateSubgroup=coordinator \
  /home/al/bull-local-tests.iI2sro/.venv/bin/python \
  /home/al/bull-evidence/production-20260922/validate.py candidate-checks
```

The retained private wrapper checks its own coordinator identity, enables only
cpu/memory/pids in its dedicated service root, initializes new validation state
with the existing collector key, verifies refused initialization on rerun, and
runs the supported checker command:

```bash
python tools/deployment_check.py --deployment "$EVIDENCE/deployment" \
  --tla-jar /home/al/bull-tla2tools-v1.7.4.jar \
  --output "$EVIDENCE/candidate-checks"
```

For the final run the wrapper's last argument is `final-checks`. The checker
runs `tools/release_check.py --tla-jar ... --output .../source-checks` and
`microvm/integration.py --case all --output .../kvm --cpu-profile host`, with
verified kernel/rootfs/firmware paths and the confirmed external endpoint and
private key-file path. Exact asset identities and source file hashes are in the
private reports. Fresh operators should use their own paths and the
[portable setup guide](REPRODUCIBLE_DEPLOYMENT.md).

### Privileges, failed attempts, and limitations

The operator explicitly provisioned `/sys/fs/cgroup/bull-1000` using the root
helper. Agent sudo attempts could not authenticate; this dedicated root-level
subtree is PROVISIONED_NOT_TESTED, not the subtree used in the passing workload
checks. Actual agent tests used a separate transient systemd **user** service
with only cpu/memory/pids delegation. Its coordinator and workloads ran as UID
1000. The transient subtree is removed on service exit. The chat and unrelated
services were not moved or restarted. Root is needed only for the alternative
administrator provisioning path and optional KVM group grant; no workloads need
root. KVM was available outside the tool sandbox.

An early memory probe failed its evidence assertion because zero-filled
allocation did not guarantee physically charged pages. The corrected bounded
probe touches each page and requires the kernel OOM-kill counter and SIGKILL
exit status. This failed preliminary probe is not counted as a pass. Final
follow-up coverage also requires an observed descendant before cancellation or
timeout, and rejection/cleanup of a real subtree with controllers disabled.

The operator confirmed the collector endpoint and supplied an existing key
file. The original file's permissions were narrowed to 0600. With explicit
operator approval, its UTF-8 encoding marker was removed only from the imported
private copy; the source file contents and deployed key were not changed. New
policy/integrity authority belongs to this separate validation installation;
no existing production authority was replaced or silently rotated.

External tests used fresh sessions and ordinary bounded checkpoints. Deliberate
collector outages/tampering stayed on disposable local infrastructure. Receipts
prove authenticated acceptance bound to session/sequence/head; no retention
period, backup restoration, disaster recovery, or independent durability was
tested. They do not independently prove the latest stored remote sequence.
The existing approval enrollment and host-display trust limits remain unchanged;
synthetic signatures are not physical hardware evidence, and touch is not proof
of informed consent. Finite tests and model checks do not establish universal
protection from malicious AI or arbitrary host compromise. No certification,
release, deployment, or merge is claimed.

## Optimization-safe cgroup evidence correction

PR review identified a validation defect in `tools/cgroup_check.py`: Python
optimization removed `assert` statements that checked resource counters,
probe exit status and scope cleanup. The ordinary-mode results above remain
observations of those specific runs; they did not establish correct behavior
under optimized Python.

The correction replaces every enforcement assertion, including the embedded
pids probe's condition, with explicit conditional errors. The regression runs
`check_limits()` in fresh normal, `-O`, `-OO`, and `PYTHONOPTIMIZE=2` interpreters.
Across those four modes, eight invalid evidence cases (CPU/memory/pids exit
status or counters, resource cleanup, descendant cleanup) must raise, while a
valid control completes. All 36 cases passed in the targeted run. These cases
use controlled fixtures and do not claim real isolation. New real-kernel rerun
reports and source evidence are kept separately under
`/home/al/bull-evidence/cgroup-optimization-20260922/`; the PR records their
commit and outcomes.

The operator's prior root-level terminal run on `978ff4d` also passed all six
real cgroup checks as UID 1000, with clean unchanged source. Its saved report,
terminal log and file manifest were inspected at
`/home/al/bull-evidence/production-20260922/root-cgroup-R7m4GV82/`.
That closes the earlier skipped path for that commit; it is not a new run of
the optimization correction. Physical-key validation remains deferred and
unverified.

Separately, GitHub reported `Workers Builds: bull` failed on `978ff4d` without
an attached error log. The operator supplied its error and configuration:
`npx wrangler versions upload`, root `/`, and “Missing entry-point to Worker
script or to assets directory”. At that revision there was no root Worker
config; the audit package is nested and named `bull-audit`.
This is a build-trigger/configuration mismatch, not a Python package install
failure or evidence that the running collector rejected audit receipts.
The [collector guide](../deploy/cloudflare-audit/README.md#workers-builds-root-directory-errors)
describes the configuration distinction. No successful Cloudflare rebuild,
production settings change, or deployment is claimed. The GitHub Pages deploy
job is intentionally skipped on PRs by its workflow condition.

Subsequent operator-supplied successful `974eb17` build logs establish that
`bull` is a separate static website mirror: `npx wrangler deploy` automatically
generated a config for `site/` and deployed 37 assets. The failed branch command
did not generate that config. Disconnecting `bull` was therefore not the fix;
the operator reports restoring its repository connection.

The local correction adds that explicit root website configuration and leaves
the collector configuration separate. Executed validation: 16 website unittest
cases passed (`python3 -m unittest discover -s tests -p 'test_*site*.py' -v`),
and `npx --offline wrangler deploy --dry-run --config wrangler.jsonc` passed
with locally cached Wrangler 4.130.0, recognizing 37 assets and no bindings.
The supplied Cloudflare logs used Wrangler 4.136.3; this local dry run is not
evidence of a successful remote build with that version. Private evidence is
under `/home/al/bull-evidence/website-config-20260922/`. No version upload or
production deployment was executed for this correction; push remains on hold.
