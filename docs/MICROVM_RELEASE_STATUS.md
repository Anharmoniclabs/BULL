# MicroVM production release status

The complete release objective is **not achieved**. These staged changes must
not be described as a working production persistent MicroVM session.

Implemented and locally verified:

- Literal deployment configuration, explicit approved export roots, canonical
  overlap checks, broad-root rejection, and engine component validation.
- Private admitted immutable workspace/runtime images by default, explicit
  development 9P, safe image publication, and read-only guest mountpoints.
- Side-effect-free diagnostics and exact-child supervision with bounded cleanup.
- Private read-write output 9P export, immutable input view, one-shot governed
  adapter and bounded no-clobber `summary.json`. Guest init checks writability
  and reaps remaining children before shutdown. The host applies a bounded
  output budget. These are host-tested changes,
  not hardware boot evidence; guest production bootstrap is still incomplete.
- Authenticated session-bound HTTPS audit transport, durable bounded SQLite
  service, host relay components, exact-last retries, conflict rejection,
  explicit checkpoint recovery, and a real local TLS fixture.
- Production runtime/dispatcher checks for the new audit transport. Legacy
  URL-only anchoring cannot satisfy production readiness. Guest relay activation
  remains disabled pending a trusted bootstrap.
- CI action commit pins, the TLA+ SHA-256 pin, and host MicroVM/audit regression
  jobs for Python 3.11 and 3.13.
- A bounded session/audit design model, separate from hardware and implementation
  verification. Existing runtime model: 405 distinct states. New design model:
  57 distinct states. Neither is a hypervisor proof.

Local verification after the output bridge: 213 tests pass, including 53
launcher/image/adapter regressions and 10 audit-service tests. Tests requiring
Unix sockets and namespaces ran outside
the development tool sandbox. A real ext4 fixture and real localhost TLS were
used. No QEMU process or guest VM was used in those tests.

Remaining implementation and release work:

1. Install a real persistent `bull-engine` and `bull microvm session` interface;
   provision trusted signed session authority separately from model requests.
2. Dedicated virtio protocol/audit ports, host socket supervision, bounded
   protocol transitions, disconnect/cancellation handling, and guest
   cgroup-controller setup beyond one-shot shutdown.
3. Signed writable authority, validated post-execution snapshot promotion,
   bounded artifact export, and the complete guest memory/storage budget.
4. Trusted guest bootstrap and credentials; activate and verify relay mode
   without fabricating direct HTTPS settings.
5. A pinned reproducible guest/kernel build, dependency inventory, hashes, and
   integrity coverage of deployed shell/init assets. The Arch bootstrap now
   derives the installed Python site-packages path, while the strict image
   builder still requires a prepared tree without symlinks.
6. A real KVM integration workflow with mandatory hardware preflight, actual
   boot/dispatcher execution, containment and failure tests, cleanup checks,
   and per-test evidence tied to the commit, QEMU, kernel, and image hashes.
7. Add KVM as a required check once its actual boot/containment job is implemented.
   The verified-signature source-and-squash path is established (audit PR #24). Main
   now requires PRs, resolved conversations, signed commits, the existing
   Python/TLA+ checks, and blocks force pushes/deletion with zero reviewer
   approvals required. Add the new MicroVM regression jobs after they land.
8. Provision and validate a production HTTPS anchor with deployment credentials.
   Local test certificates/keys are not production deployment evidence.

The tool sandbox hides `/dev/kvm`; a subsequent check outside it confirmed the
host KVM device exists and is accessible. QEMU is still absent: the host setup
attempt stopped because sudo requires a local password. The new CachyOS/Arch
`microvm/setup-host-deps.sh` supports installation and read-only checks without
restarting any session. Guest assets and production bootstrap remain unprovisioned.
GitHub runner hardware capability
still needs an actual boot test. Linux x86-64/KVM is the intended first release;
macOS/HVF and ARM remain disabled/experimental. HVF certification and independent
hypervisor assessment remain prerequisites for their respective claims.
