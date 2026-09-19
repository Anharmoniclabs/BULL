# BULL MicroVM launcher

The release target is Linux x86-64 with real KVM. This launcher is not yet a
certified persistent production session. ARM and macOS/HVF remain experimental
and are disabled. Software emulation is never used as a fallback.

The default launch attaches three read-only ext4 disks: rootfs, admitted
workspace, and admitted trusted runtime. Workspace/runtime images are built
from private snapshots with BULL's file-count, size, depth, hardlink,
special-file, symlink, and source-mutation checks. No live host tree is attached
unless the deployment explicitly enables development 9P mode. QEMU gets no
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
substitutions, inline comments, duplicate keys, or unknown keys. Documented
keys are `APPROVED_WORKSPACE_ROOT`, `APPROVED_RUNTIME_ROOT`, `WORKSPACE`,
`RUNTIME_DIR`, `KERNEL`, `ROOTFS`, `ENGINE_GUEST`, `MEMORY_MIB`, `CPUS`, `ACCEL`,
`QEMU`, `TIMEOUT_SECONDS`, and `DEV_9P`. For non-approval settings, precedence is
flags, environment, configuration, defaults. `BULL_MICROVM_CONFIG_FILE` selects
the configuration when `--config` is absent.

```sh
microvm/run-bull-microvm.sh \
  --config /srv/bull/deployment.env \
  --kernel /srv/bull/assets/vmlinux \
  --rootfs /srv/bull/assets/rootfs.ext4 \
  --workspace /srv/bull/projects/example \
  --bull-runtime /srv/bull/runtime/release
```

The engine defaults to `/bull_runtime/bin/bull-engine`. Every relative engine
component must be normalized and free of symlinks. The launcher checks this
with kernel-constrained file opens; guest init checks each component and the
canonical path again. A trusted engine is still an explicit deployment input;
the example adapter is not a persistent production engine.

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
policies. The guest needs `/bin/sh`, mount utilities, `readlink`, and the
engine's interpreter/libraries; its kernel needs ext4, devtmpfs, procfs, sysfs,
tmpfs, and virtio-mmio/block built in. 9P is only needed for development mode.

The VM contains guest workloads relative to the host. It does not protect
against a malicious host or prove the absence of hypervisor vulnerabilities.
Keep the guest kernel, QEMU, runtime, and images pinned as one release stack.

Host regression tests: `python -m pytest -q tests/test_microvm.py`. These are
separate from KVM boot evidence, which has not yet been produced.
