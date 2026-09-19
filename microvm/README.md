# BULL MicroVM launcher

The release target is Linux x86-64 with real KVM. This launcher is not yet a
certified persistent production session. ARM and macOS/HVF remain experimental
and are disabled. Software emulation is never used as a fallback.

On CachyOS/Arch, run `./microvm/setup-host-deps.sh` as your normal user to
install host packages and enable KVM access where needed. It uses sudo and may
ask for your local password. `--check` is read-only; `--non-interactive` fails
if sudo authentication is required. It does not restart sessions, reboot, build
images, or provision production credentials. If group membership changes,
apply it in a new login session when convenient; restarting only a terminal
inside an existing desktop session may not refresh its inherited groups.

The default launch attaches three read-only ext4 disks: rootfs, admitted
workspace, and admitted trusted runtime. Workspace/runtime images are built
from private snapshots with BULL's file-count, size, depth, hardlink,
special-file, symlink, and source-mutation checks. A separate private output
directory is attached read-write using 9P. Live input trees require explicit
development 9P mode. QEMU gets no
network device, no monitor, minimal devices, and its Linux seccomp sandbox.

Copy `config/defaults.env` to an owner-controlled deployment file and add:

```text
BULL_MICROVM_APPROVED_WORKSPACE_ROOT=/srv/bull/projects
BULL_MICROVM_APPROVED_RUNTIME_ROOT=/srv/bull/runtime
```

Both directories must exist. These approvals can only come from the explicitly
selected configuration file; environment variables and launch flags cannot
widen them. Selected exports must be beneath those roots and must not overlap.
Root, home-directory roots, broad system directories, and aliases of those
paths are rejected. The runtime and approved deployment configuration must be
controlled by the deployment administrator, not the workload.

Configuration is literal `BULL_MICROVM_KEY=value`, with no quotes, expansions,
substitutions, inline comments, duplicate keys, or unknown keys. `KERNEL`,
`ROOTFS`, `QEMU`, and `ENGINE_GUEST` are trusted deployment assets and must be
pinned in this file; flags and environment variables cannot override them.
Documented
keys are `APPROVED_WORKSPACE_ROOT`, `APPROVED_RUNTIME_ROOT`, `WORKSPACE`,
`RUNTIME_DIR`, `KERNEL`, `ROOTFS`, `ENGINE_GUEST`, `MEMORY_MIB`, `CPUS`, `ACCEL`,
`QEMU`, `TIMEOUT_SECONDS`, `OUTPUT_DIR`, `OUTPUT_MAX_BYTES`, and `DEV_9P`. For non-approval settings, precedence is
flags, environment, configuration, defaults. `BULL_MICROVM_CONFIG_FILE` selects
the configuration when `--config` is absent.

```sh
microvm/run-bull-microvm.sh \
  --config /srv/bull/deployment.env \
  --workspace /srv/bull/projects/example \
  --bull-runtime /srv/bull/runtime/release
```

The engine defaults to `/bull_runtime/bin/bull-engine`. Every relative engine
component must be normalized and free of symlinks. The launcher checks this
with kernel-constrained file opens; guest init checks each component and the
canonical path again. A trusted engine is still an explicit deployment input;
the supplied adapter executes one governed command per boot, not a persistent
production session.

## One-shot workload and output bridge

Install `guest/engine-adapter.example.sh` as the trusted runtime's
`bin/bull-engine` with mode 0555. Despite its historical filename, this is now
an executable adapter, not a placeholder. Install the BULL Python package into
the guest's `/usr/bin/python3` environment; isolated Python ignores workspace
imports and `PYTHONPATH`. Add a trusted runtime `workload.json`:

```json
{"version":1,"argv":["/usr/bin/printf","hello\\n"],"timeout_seconds":30,"task":"Print a greeting"}
```

The executable must exist in the guest's execution environment. Arguments are
literal: no implicit shell. Configuration is limited to these four keys; grants,
provenance, environment overrides, unknown and duplicate keys are rejected.
The 16 KiB configuration permits up to 128 arguments and a 1–300 second timeout.
The adapter constructs `ProductionRuntime` and `ProductionDispatcher`, binds the
entire argv to a new security domain, and derives authority from the signed
deployment ceiling. It does not fall back to unrestricted subprocess execution.

**Production bootstrap remains incomplete.** Signed policy/integrity assets,
namespace attestation, cgroups and audit transport must pass the existing gates.
The networkless guest still lacks provisioned audit relay activation; direct
HTTPS cannot work without guest networking. This change does not enable that
relay or certify a successful production boot. Missing bootstrap produces an
`infrastructure_failure` report with `executed: false`.

The launcher creates `./project_outputs/` by default, relative to its working
directory. Use `--output-dir /absolute/path/to/new-output` or
`BULL_MICROVM_OUTPUT_DIR` to choose another location. Its parent must already
exist, be owned by the launcher user and not group/world writable. The output
directory must be empty, owned by that user with mode 0700, have no symlink
components, and be separate from inputs, runtime and deployment assets. Launch
from outside the source workspace or select a separate output path. Existing
reports are never overwritten; choose a new directory for another run.

QEMU receives a pinned directory descriptor and an exclusive session lock.
The export uses `mapped-xattr`, so the backing filesystem must support user
extended attributes. This keeps guest ownership metadata in xattrs and host
files private; see the [QEMU 9P options](https://www.qemu.org/docs/master/system/invocation.html).
The guest mounts it at `/workspace/outputs` with `rw,nosuid,nodev,noexec`, checks
the mount and performs a write/read/delete probe. All input disks stay read-only.
A separate non-recursive read-only bind at `/run/bull-input` excludes the output
mount from workspace admission. Signed project-root configuration must match
that input path. Workloads receive an admitted read-only snapshot; the trusted
adapter writes the report after dispatch, rather than exposing this host mount
to the sandboxed workload.

`summary.json` contains a version, status, execution flag, return code, decision,
bounded reasons, duration, stdout/stderr and truncation flags. Each output stream
is capped at 8192 characters in the report. Status distinguishes success, policy
denial, review, execution failure, timeout and infrastructure failure. An
interrupted dispatch can have `executed: null` (unknown outcome); never retry
automatically. Reports publish atomically without replacement. An interrupted
write can leave `.bull-summary.pending`; a boot/mount failure or host timeout
may leave no report. Guest init syncs and requests poweroff after the adapter
exits, including failure exits. The host retains outputs for diagnosis.
QEMU's exit status describes the VM lifecycle; read the report's status to
determine whether the workload succeeded.

This exports execution reports only; arbitrary generated files and private
writable workspace promotion remain separate work. The 9P export is a live
host write surface, not a network interface. The launcher applies a 1 MiB
per-file limit to QEMU and rejects an output directory that exceeds the
configured `OUTPUT_MAX_BYTES` budget after the VM exits. Deployments requiring
a hard storage guarantee should still place the output directory on a
quota-limited filesystem.

`--print-command` validates configuration and paths and prints the planned
command with `/PRIVATE_RUN_DIRECTORY` placeholders. It does not create images,
create temporary directories, probe QEMU, or start a VM. Its output explicitly
says hardware was not checked. A real launch requires read/write `/dev/kvm`.
The launcher supervises the exact QEMU child, forwards termination signals,
enforces a lifetime limit, and removes its temporary assets. Guest PID 1 waits
for and reaps remaining child processes before shutdown.

Defaults are 4096 MiB, 2 CPUs, and a 3600-second maximum VM lifetime. Memory is
bounded to 4096–65536 MiB, CPUs to 1–64, lifetime to 1–86400 seconds. These launch
limits do not yet constitute a validated persistent-session storage budget.

For development only, use `--dev-9p` or literal `BULL_MICROVM_DEV_9P=true`.
The same approved-root restrictions apply. Live read-only 9P exposes changing
host trees and is not a production image-isolation substitute.
Development workspaces must already contain an empty real `outputs` directory.
Immutable workspace images get that mountpoint in their private staged copy,
without changing the source workspace. Nonempty source `outputs` is rejected.

## Building rootfs images

On CachyOS/Arch, the checked-in bootstrap recipe builds a separate guest tree
from explicit packages and then invokes the strict image builder:

```sh
microvm/rootfs/build-arch-rootfs.sh \
  --output /srv/bull/assets/rootfs.ext4
```

It requires `arch-install-scripts` (`pacstrap`) and sudo. It does not use the
host root as input. The package set, materialized files, copied BULL package,
and resulting image should be recorded as deployment assets and reviewed before
use. It intentionally excludes systemd and host-runtime links; guest PID 1 is
the checked-in shell supervisor. It deliberately does not invent signed production policy, integrity
manifests, audit credentials, or a successful production bootstrap.

```sh
microvm/rootfs/build-ext4.sh \
  --source /srv/bull/assets/rootfs-tree \
  --output /srv/bull/images/rootfs.ext4
```

The existing output parent must be owned by the builder and not group/world
writable. Output parents may not contain symlinks; output directories must be
outside the source. Existing outputs (including dangling links) are rejected;
there is no replacement option. The builder creates private scratch and a
private temporary image, then publishes the complete image with atomic
no-clobber semantics. Failed builds clean up scratch and do not publish output.

The strict admitted-tree builder currently rejects all symlinks, including
usual merged-usr rootfs links. Supply a prepared tree of regular files and
directories. It installs `/sbin/bull-init` and all guest mountpoints before
formatting. It does not download a userspace, pin a kernel, or provision signed
policies. The guest needs `/bin/sh`, util-linux mount (including bind/remount
and propagation options), `readlink`, `awk`, `mktemp`, `cat`, `rm`, `sync`,
`sleep`, `poweroff`, and the installed Python/BULL engine and its libraries.
Its kernel needs ext4, devtmpfs, procfs, sysfs, tmpfs, virtio-mmio/block,
9P/virtio transport and xattr support built in. Rebuild old rootfs images to
install the updated init; passing an old prebuilt image does not update it.

The VM contains guest workloads relative to the host. It does not protect
against a malicious host or prove the absence of hypervisor vulnerabilities.
Keep the guest kernel, QEMU, runtime, and images pinned as one release stack.

Host regression tests: `python -m pytest -q tests/test_microvm.py`. These are
separate from KVM boot evidence, which has not yet been produced.
