# Source and binary distribution

## Source repository

Original BULL source is GPL-2.0-or-later. Preserve LICENSE and the
[third-party notices](../THIRD_PARTY_NOTICES.md). Python packages include the README,
license and notices. Dependencies obtained separately keep their upstream terms.
The repository is public, and private vulnerability reporting is enabled.

## Guest binary releases

The historical `guest-2026-09-22` release contains image hashes and build metadata,
but its inspected asset list contains no source/license bundle. This is an open
redistribution-readiness gap; do not present it as a completed compliance delivery.
Its runtime test results do not resolve source-distribution obligations.

Future guest builds collect Buildroot `legal-info`, pinned Buildroot and qboot
source archives, BULL source, actual build inputs and resolved configuration into
a separate bundle. The workflow creates a **draft prerelease**, not an automatic
public release. Before publishing it:

1. Inspect target and host manifests, license texts, source archives and warnings.
2. Resolve missing/nonredistributable sources and retain required notices. Check
   packages, patches, toolchains, firmware and signature-database terms against
   the actual binary build; do not infer completeness from a successful command.
3. Verify the bundle and image hashes, exact source revisions and reproduction
   instructions. Preserve the scripts and configs used to build those images.
4. Qualify the guest on the supported host and retain the separate hardware and
   deployment evidence. Publish only artifacts cleared for redistribution.

Buildroot documents both what `legal-info` collects and its limitations in its
[licensing chapter](https://buildroot.org/downloads/manual/manual.html#legal-info).
A recipe link alone is not the supplied corresponding-source bundle. This process
is an engineering release control, not independent legal certification.

Do not attach host credentials, collector keys, private deployment state, local
logs or model weights to a source/license bundle. Fix historical binary evidence
with materials matching that historical build, not a newer unrelated build.
