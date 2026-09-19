# MicroVM production release status

The complete release objective is **not achieved**. These staged changes must
not be described as a working production persistent MicroVM session.

Implemented and locally verified:

- Literal deployment configuration, explicit approved export roots, canonical
  overlap checks, broad-root rejection, and engine component validation.
- Private admitted immutable workspace/runtime images by default, explicit
  development 9P, safe image publication, and read-only guest mountpoints.
- Side-effect-free diagnostics and exact-child supervision with bounded cleanup.
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

Local verification: 185 tests pass, including 26 launcher/image regressions and
9 audit-service tests. Tests requiring Unix sockets and namespaces ran outside
the development tool sandbox. A real ext4 fixture and real localhost TLS were
used. No QEMU process or guest VM was used in those tests.

Remaining implementation and release work:

1. Install a real persistent `bull-engine` and `bull microvm session` interface;
   provision trusted signed session authority separately from model requests.
2. Dedicated virtio protocol/audit ports, host socket supervision, bounded
   protocol transitions, disconnect/cancellation handling, and guest PID-1
   supervision with cgroup-controller setup.
3. Signed writable authority, validated post-execution snapshot promotion,
   bounded artifact export, and the complete guest memory/storage budget.
4. Trusted guest bootstrap and credentials; activate and verify relay mode
   without fabricating direct HTTPS settings.
5. A pinned reproducible guest/kernel build, dependency inventory, hashes, and
   integrity coverage of deployed shell/init assets. The current strict image
   builder requires a prepared tree without symlinks; it is not a guest build
   recipe.
6. A real KVM integration workflow with mandatory hardware preflight, actual
   boot/dispatcher execution, containment and failure tests, cleanup checks,
   and per-test evidence tied to the commit, QEMU, kernel, and image hashes.
7. Finish protected merges after establishing the verified-signature path and
   actual required jobs; add KVM as a required check once implemented.
8. Provision and validate a production HTTPS anchor with deployment credentials.
   Local test certificates/keys are not production deployment evidence.

The local machine has no `/dev/kvm` or QEMU. GitHub runner hardware capability
still needs an actual boot test. Linux x86-64/KVM is the intended first release;
macOS/HVF and ARM remain disabled/experimental. HVF certification and independent
hypervisor assessment remain prerequisites for their respective claims.
