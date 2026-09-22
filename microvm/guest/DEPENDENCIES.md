# Production guest dependency contract

For new installations, use [`build_public.py`](build_public.py) and the
[public reproduction workflow](../../docs/REPRODUCIBLE_DEPLOYMENT.md). It contains
complete source configs, pinned public Buildroot/Linux/qboot inputs and verified
offline-database import. It has no dependency on the historical R3 baseline.
The private-baseline derivation below remains historical; its previously measured
guest results do not qualify a newly built public image.

The R3 guest is insufficient for ProductionRuntime. The production.fragment
adds the missing Bash and ClamAV build selections to the pinned Buildroot
configuration. The complete local recipe additionally needs verified offline
databases and the `/usr/share/clamav` alias created by prepare_build.py.
ClamAV's Config.in additionally selects Rust, JSON-C, curl, libmspack, libxml2,
OpenSSL, PCRE2, bzip2 and zlib; Bash selects ncurses and readline. Build from
verified cached sources into a new output directory. Never reuse the original
R3 output directory or let a build silently download missing dependencies.

The installed ClamAV executable also needs an admitted, versioned signature
database. A fabricated scanner or empty substitute database is not sufficient.
No boot-time updater is permitted. Record database hashes with image hashes.

Required guest functionality:

* Python: ssl, sqlite3, ctypes, fcntl and resource, plus all BULL production
  modules. libseccomp must load and install the existing strict filter.
* Bash with pipefail; do not change the namespace launcher's interpreter to sh.
* mount with recursive bind and propagation controls; unshare with user mapping,
  mount, PID, fork, network and IPC namespace options; chroot, true, mkdir,
  readlink, dirname, chmod, touch, ln, rm, env and reboot.
* Kernel: user/mount/PID/net/IPC namespaces, seccomp filters, Landlock,
  cgroup v2 memory/pids/cpu controllers, ext4, tmpfs, virtio-mmio block devices.
  Virtio console is additionally required for the dedicated audit/control relay.
* Guest-private bounded writable snapshot/audit scratch and a cgroup delegation.
  Init provisions these before admission; rootfs, workspace and runtime remain
  read-only.
* Signed policy, signed TCB manifest, separately provisioned verification keys,
  session-bound authority, and acknowledged authenticated audit transport.

Guest init invokes bulldog.guest_preflight from /bull_runtime/src before the
engine. The preflight checks functionality and fails with exit 78. Its JSON is
diagnostic data only, never authenticated completion evidence. The public
ProductionRuntime gates still run afterwards. Dynamic checks report this
kernel's measurements; no host values are substituted. The v3 integration
validated the built dependencies and actual production dispatch; see
../../docs/MICROVM_INTEGRATION_REPORT.md for scope and evidence.

The minimal rebuilt kernel should omit unused CONFIG_IPV6_SIT; retain the
namespace boundary and no-NIC QEMU configuration. R3's down, unrouted sit0 is
not evidence of a network escape. Do not change host networking.

With download approval, prepare_build.py creates a separate pinned build and
Buildroot verifies its source downloads. Official main/daily/bytecode databases
must be downloaded and verified with FreshClam into the new overlay's
var/lib/clamav directory before image creation. No boot-time network updater
is used. finalize_build.py records input, output and database hashes and checks
the original assets remain intact. Building is not guest execution evidence.

ClamAV 1.5.4 loading the full database failed under the previous 768 MiB scanner
address-space ceiling. A bounded 1536 MiB host sizing probe succeeded with
996848 KiB peak RSS; the scanner ceiling is now 1536 MiB. Workload limits remain
512 MiB and separate. Guest preflight must independently pass the actual scan.
