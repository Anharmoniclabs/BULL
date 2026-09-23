# Validation recorded 2026-09-23

Tested clean commit: `428db9cf8740f755249b23d33ba71da0c39502b1`.
[Published operator report](https://github.com/Anharmoniclabs/BULL/pull/55#issuecomment-5794436540).
Machine-readable, sanitized results: [candidate-428db9c.json](evidence/candidate-428db9c.json).

| Scope | Result |
|---|---|
| Local source checks | 437 tests + 6 subtests; zero failures/skips; three bounded formal models; wheel/site builds passed |
| GitHub validation | Seven jobs passed on the same commit; Pages deployment skipped |
| Production configuration | Signed authority, strict host checks and real cgroup enforcement passed |
| Real KVM | Allowed, denied, timeout, cancellation and missing protection passed |
| External collector | Authenticated host and guest receipts passed against the existing live collector |
| Fixed-tool adapter | Inspect/checksum allowed; empty-grant request denied |
| Controlled recovery | Seven new storage, worker and disposable collector cases passed |
| Fresh guest after cancellation | Passed as a distinct one-shot session; no persistent VM state recovery claim |
| Physical key | BLOCKED; not an all-gates release approval |

Tracked source content SHA-256:
`960ad2ac7cec7ea0f30003c065120a0594c1bdf4bb0be6118199c56456d3f8b4`.
Guest runtime tree SHA-256:
`503c2e662931dd958b30932be3b3f0ce6439c3e4dd910a6857174e07c56a0603`.
Guest kernel/rootfs/firmware hashes and exact CI URLs are in the JSON summary.
Documentation and packaging follow-ups do not retroactively change this tested commit.

## Retained failures

The first run lacked setuptools and a scanner on PATH. One guest scanner timed
out; another lost its audit relay. A retry's nested output path exceeded Linux's
Unix-socket limit. After installing verified dependencies and choosing a shorter
output path, the complete unchanged-candidate run passed every nonhardware
automated deployment gate. Earlier failures were retained, not relabeled.

Use short private evidence paths for MicroVM runs, such as `/tmp/bull-check-01`;
the runner creates Unix sockets beneath the output directory.

## Limits

Storage tests inject ENOSPC/EIO; they do not reproduce physical disk failure.
Collector restart uses disposable loopback TLS and retained SQLite state; it is
not a disaster-recovery audit of the production collector. No host reboot or
power-loss test was performed. Runtime tests do not establish arbitrary-adapter
coverage, multi-day reliability or independent security certification.

The rejected collector preview remains unpromoted. The historical Qwen run and
its 380-test snapshot remain [separate evidence](evidence/governed-agent-20260922/README.md).
