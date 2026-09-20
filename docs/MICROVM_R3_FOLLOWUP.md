# Historical R3 follow-up: partial implementation

This records the earlier investigation. Its outstanding execution status is
superseded by [the completed local integration report](MICROVM_INTEGRATION_REPORT.md).

The one-shot ProductionDispatcher-in-KVM milestone is **not achieved**.
This patch does not replace it with a diagnostic pass.

## Resolved source defects

The literal configuration parser now permits digits after the first key
character, so the shipped DEV_9P key parses. Allowed-key checks, duplicate
rejection and literal-only values remain. A regression reads the shipped file.

The repository Python launcher now selects the qboot direct-kernel profile:
`microvm,acpi=off,x-option-roms=off,auto-kernel-cmdline=on`. This is not a guest
kernel `acpi=off` argument. QEMU's microvm implementation selects bios-microvm.bin
when ACPI is enabled and qboot.rom otherwise; its automatic virtio-mmio
command-line discovery is the non-ACPI path. R3 relied on that path and the
guest's CONFIG_X86_MPPARSE support. Sources:
https://github.com/qemu/qemu/blob/master/hw/i386/microvm.c and
https://www.qemu.org/docs/master/system/i386/microvm.html .

Deployment configuration must explicitly pin FIRMWARE and FIRMWARE_SHA256.
The launcher rejects unsafe files and digest mismatches, then copies the
verified bytes to private run scratch before QEMU opens them. Neither firmware
authority nor approved export roots can come from environment overrides.
The shell wrapper still delegates to the repository Python implementation.

Guest init runs a fail-closed functional dependency preflight before the engine.
Failure uses reboot (the qboot/-no-reboot contract), not ACPI poweroff.
The preflight itself is covered by the TCB manifest. This is a prerequisite,
not an execution engine, completion protocol or hardware attestation.

## CPU dependency correction

Linux 7.1.13 cpufeatures.h maps 18*32+31 to SPEC_CTRL_SSBD and 18*32+26
to SPEC_CTRL. cpuid-deps.c explicitly requires the latter for the former.
A paused diskless KVM check using `host,spec-ctrl=on,enforce` was rejected:
the host does not support CPUID.07H.EDX.spec-ctrl bit 26. No mitigation was
disabled and no warning was suppressed. A subsequent diskless KVM boot with
`host,ssbd=off,amd-ssbd=on,enforce` retained the guest's speculative-store-bypass
mitigation and removed the invalid dependency. The repository now supports
this as the explicit trusted `CPU_PROFILE=amd-native-ssbd` profile. It checks
AMD host identity and SSBD availability; QEMU enforce rejects unsupported
features. This probe does not establish full dispatcher execution.

## Outstanding one-shot execution work

The guest engine now calls the public ProductionRuntime and ProductionDispatcher
entry points. The supervisor opens dedicated virtio control/audit ports and
requires an authenticated bootstrap acknowledgment before admitting a request.
Relay mode cannot be enabled by environment fields alone. Signed policy and
integrity gates remain mandatory. The integration runner provisions disposable
test authority and a local TLS collector; this validates only a test collector,
never an external production audit service.

Guest init provisions bounded private scratch and cgroup v2. The separate
Buildroot image is being built with Bash, ClamAV and official verified offline
databases. Allowed and denied workloads must still be validated through the
real ProductionDispatcher in KVM. Test result parsing uses the control channel, never serial/workload
output. VM exit zero is not workload completion. Missing acknowledgments,
malformed completion, timeout and cancellation must fail closed.

Required evidence still absent: allowed guest dispatch, refused guest dispatch,
guest strict-sandbox measurements, bounded authenticated completion, audit
acknowledgment, and cleanup across timeout/cancellation. Their timings are
NOT MEASURED. Prior host namespace timings are not MicroVM timings.

The implemented local runner is `PYTHONPATH=src .venv/bin/python microvm/integration.py`.
It requires `--kernel`, `--rootfs`, `--firmware`, a new private `--output`
directory and `--case allowed` or `--case denied`. On the verified AMD host,
also select `--cpu-profile amd-native-ssbd`. Each invocation creates one new
session and disposable test credentials; it does not reuse a VM or request.
It writes a private report, boot log, source-file hashes and collector evidence.
Do not add those artifacts or the generated deployment to Git.

The runner expects a fresh complete result from the authenticated channel and
checks the final audit head against the test collector. Missing evidence,
guest errors and interrupted runs remain failures. Its launch-to-dispatcher
readiness timing includes preflight and production gates; it is not relabeled
as pure VM boot latency. The fixture's own duration is separately labeled and
is not hardware-backed timing evidence.

Persistent reuse is deferred. It will require authorization per request,
expiration/revocation, limits per session, no credential/state sharing, defined
guest/relay/collector failure handling, and no unsafe replay of interrupted work.

The previous /tmp result only established denial of direct execution under the
tested conditions; it says nothing about all interpreted code. No syscall
allowlist changes or new escape probes are part of this patch.
