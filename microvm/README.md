# BULL MicroVM launcher

The supported local integration target is Linux x86-64 with real KVM. Five
real guest cases passed through the one-shot production dispatcher path;
persistent sessions remain deferred. ARM and macOS/HVF remain experimental
and are disabled. Software emulation is never used as a fallback.

The default launch attaches three read-only ext4 disks: rootfs, admitted
workspace, and admitted trusted runtime. Workspace/runtime images are built
from private snapshots with BULL's file-count, size, depth, hardlink,
special-file, symlink, and source-mutation checks. No live host tree is attached
unless the deployment explicitly enables development 9P mode. QEMU gets no
network device, no monitor, minimal devices, and its Linux seccomp sandbox.

## Local-only deployment assets

Keep guest images, kernels, prepared rootfs trees, and real deployment
configuration outside this repository. The repository contains source code
and templates, not your local VM or its filesystem contents. All host paths
below are placeholders; replace them only in your private deployment file or
local shell commands, not in committed documentation.

The repository ignore rules exclude common VM image formats, local MicroVM
asset directories, and private deployment configuration files. Do not use
`git add --force` for these assets. Before committing or pushing, run:

```sh
python -m unittest discover -s tests -p test_repository_artifacts.py -v
```

The same check runs in MicroVM CI and rejects tracked local assets, including
force-added files. Ignore rules and CI do not erase files from earlier commits;
CI runs after a push and is not a server-side upload prevention mechanism.

Copy `config/defaults.env` to an owner-controlled deployment file outside the
repository and add your real absolute approved roots. For example:

```text
BULL_MICROVM_APPROVED_WORKSPACE_ROOT=/absolute/path/to/private/projects
BULL_MICROVM_APPROVED_RUNTIME_ROOT=/absolute/path/to/private/runtime
```

Both directories must exist. These approvals can only come from the explicitly
selected configuration file; environment variables and launch flags cannot
widen them. Selected exports must be beneath those roots and must not overlap.
Root, home-directory roots, broad system directories, and aliases of those
paths are rejected. The runtime and approved deployment configuration must be
controlled by the deployment administrator, not the workload.

Configuration is literal `BULL_MICROVM_KEY=value`, with no quotes, expansions,
substitutions, inline comments, duplicate keys, or unknown keys. Documented
keys are `APPROVED_WORKSPACE_ROOT`, `APPROVED_RUNTIME_ROOT`, `WORKSPACE`,
`RUNTIME_DIR`, `KERNEL`, `ROOTFS`, `ENGINE_GUEST`, `MEMORY_MIB`, `CPUS`, `ACCEL`,
`QEMU`, `TIMEOUT_SECONDS`, `DEV_9P`, `FIRMWARE`, `FIRMWARE_SHA256`, `CPU_PROFILE`,
`CONTROL_SOCKET`, and `AUDIT_SOCKET`. Firmware, CPU profile and channel settings
come only from trusted configuration, as do approved roots. For other settings, precedence is
flags, environment, configuration, defaults. `BULL_MICROVM_CONFIG_FILE` selects
the configuration when `--config` is absent.

```sh
microvm/run-bull-microvm.sh \
  --config /absolute/path/to/private/deployment.env \
  --kernel /absolute/path/to/private/assets/vmlinux \
  --rootfs /absolute/path/to/private/images/guest.ext4 \
  --workspace /absolute/path/to/private/projects/example \
  --bull-runtime /absolute/path/to/private/runtime/release
```

The engine defaults to `/bull_runtime/bin/bull-engine`. Every relative engine
component must be normalized and free of symlinks. The launcher checks this
with kernel-constrained file opens; guest init checks each component and the
canonical path again. A trusted engine is still an explicit deployment input;
the shipped `guest/bull-engine` starts the real one-shot production supervisor.
Provision its immutable session authority, signed policy and integrity manifest
in the runtime image. The integration runner supplies disposable test authority.

Pin `FIRMWARE` and `FIRMWARE_SHA256` in trusted configuration. The implementation
uses qboot with the non-ACPI microvm boot contract. The optional `amd-native-ssbd`
CPU profile corrects the verified AMD/KVM SSBD dependency with enforced hardware
support; `host` is the default. Paired control/audit paths must be distinct
owner-only Unix sockets in private directories.

`--print-command` validates configuration and paths and prints the planned
command with `/PRIVATE_RUN_DIRECTORY` placeholders. It does not create images,
create temporary directories, probe QEMU, or start a VM. Its output explicitly
says hardware was not checked. A real launch requires read/write `/dev/kvm`.
The launcher supervises the exact QEMU child, forwards termination signals,
enforces a lifetime limit, reaps the child, and removes its temporary assets.

Defaults are 4096 MiB, 2 CPUs, and a 3600-second maximum VM lifetime. Memory is
bounded to 4096–65536 MiB, CPUs to 1–64, lifetime to 1–86400 seconds. These launch
limits do not yet constitute a validated persistent-session storage budget.

For development only, use `--dev-9p` or literal `BULL_MICROVM_DEV_9P=true`.
The same approved-root restrictions apply. Live read-only 9P exposes changing
host trees and is not a production image-isolation substitute.

## Building rootfs images

Build into an existing private directory outside the checkout. The output
below is the same local image passed to `--rootfs` in the launch example:

```sh
microvm/rootfs/build-ext4.sh \
  --source /absolute/path/to/private/rootfs-tree \
  --output /absolute/path/to/private/images/guest.ext4
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
policies. The guest needs `/bin/sh`, mount utilities, `readlink`, and the
engine's interpreter/libraries; its kernel needs ext4, devtmpfs, procfs, sysfs,
tmpfs, and virtio-mmio/block built in. 9P is only needed for development mode.

The VM contains guest workloads relative to the host. It does not protect
against a malicious host or prove the absence of hypervisor vulnerabilities.
Keep the guest kernel, QEMU, runtime, and images pinned as one release stack.

For the complete guest, use the pinned Buildroot scripts under `guest/` and
[the dependency contract](guest/DEPENDENCIES.md). They cover Bash, offline
ClamAV databases, Python dependencies and guest kernel features. Preserve
existing assets and use new versioned output paths.

## Reproduce the local KVM suite

With prepared assets outside Git, run from the repository root:

```sh
PYTHONPATH=src python3 microvm/integration.py \
  --kernel /absolute/path/to/private/images/bzImage \
  --rootfs /absolute/path/to/private/images/rootfs.ext4 \
  --firmware /absolute/path/to/private/qboot.rom \
  --output /absolute/path/to/private/new-integration-run \
  --case all --cpu-profile host
```

Select `amd-native-ssbd` only for the supported AMD configuration. The output
directory must be new. The runner requires QEMU/KVM, Python, OpenSSL and ext4
image tools; it starts a disposable local TLS collector automatically. It adds
no guest NIC and does not contact an external collector. Cases are `allowed`,
`denied`, `timeout`, `cancel`, and `missing-protection`. Completion requires
authenticated results and audit evidence; QEMU exit status alone cannot pass.

Host regressions: `python -m pytest -q`. Recorded results are 217 tests plus two
subtests passing, separately from five passing KVM cases. The
[integration report](../docs/MICROVM_INTEGRATION_REPORT.md) records source and
asset identities, timings, limitations and the exact locally tested command.
Credentials, images and raw reports stay outside Git.
