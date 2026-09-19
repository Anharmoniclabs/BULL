# Local BULL MicroVM

This layout runs a Linux guest inside QEMU's `microvm` machine type. The host
must provide hardware virtualization: KVM on Linux or Hypervisor.framework on
macOS. The launcher refuses software emulation and refuses to start if the
accelerator is unavailable.

The guest kernel and root filesystem are supplied locally. The root filesystem
is opened read-only. The host `workspace` and trusted `bull_runtime` trees are
exported through read-only virtio-9p devices and mounted in the guest at the
same paths. The guest has no network device. `/run` and `/tmp` are private
guest tmpfs mounts.

```
microvm/
├── config/defaults.env       # non-secret local defaults
├── guest/init                # guest PID 1, copied into the rootfs image
├── guest/engine-adapter.example.sh
├── rootfs/build-ext4.sh      # optional Linux-side rootfs image builder
└── run-bull-microvm.sh       # host launcher
```

The engine is deliberately an explicit input. This repository currently
provides BULL's Python runtime and namespace backend, but it does not provide a
standalone `bull run` daemon or guest executable. Put a reviewed executable at
`<trusted-runtime>/bin/bull-engine`, or pass another executable path below
`/bull_runtime` with `--engine`. The guest init invokes it as:

```
/bull_runtime/.../engine --workspace /workspace --runtime /bull_runtime
```

The engine must be part of the read-only trusted runtime tree. Workspace files
cannot select the engine, and symlinked engine paths are rejected.

## Guest assets

Provide a kernel matching the host architecture and a minimal Linux rootfs
directory or raw ext4 image. The guest kernel needs the virtio-mmio, virtio
block, virtio-9p, 9P filesystem, devtmpfs, procfs, sysfs, and tmpfs support
needed by `guest/init`. The rootfs must contain `/bin/sh`, `mount`, `sleep`, and
the interpreter and libraries required by the trusted engine.

On Linux, a prepared rootfs directory can be converted into a read-only ext4
image without root:

```
microvm/rootfs/build-ext4.sh \
  --source /path/to/minimal-rootfs \
  --output /path/to/rootfs.ext4
```

The helper adds `microvm/guest/init` as `/sbin/bull-init`. A prebuilt image
must already contain that file, or a rootfs build step must install it.

## Run locally

```
microvm/run-bull-microvm.sh \
  --kernel /path/to/vmlinux \
  --rootfs /path/to/rootfs.ext4 \
  --workspace /path/to/project \
  --bull-runtime /path/to/trusted/bull-runtime \
  --engine /bull_runtime/bin/bull-engine
```

Use `--print-command` to inspect the exact QEMU invocation. The launcher uses
`qemu-system-x86_64 -M microvm` on x86 hosts and `qemu-system-aarch64 -M
virt` on ARM hosts, with the host-native accelerator selected explicitly. It
does not add a user-mode or tap network backend.

For the strongest directory isolation, build immutable workspace and runtime
disk images and attach them as read-only virtio block devices in a Firecracker
or QEMU configuration. The default 9P exports here are intentionally read-only
and are useful for a local development loop, but QEMU remains the host-side
file server for those exports and therefore stays in the trusted computing
base.

This layer protects the BULL guest from a compromised host workload only to the
extent provided by the host hypervisor, QEMU, KVM/HVF, and the guest kernel.
It does not make those components untrusted or eliminate hypervisor breakout
risk. Keep the guest kernel, QEMU, and BULL runtime pinned and update them as
one security-sensitive stack.
