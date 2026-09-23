# Source and binary distribution

## Source repository

Original BULL source is GPL-2.0-or-later. Preserve LICENSE and the
[third-party notices](../THIRD_PARTY_NOTICES.md). Python packages include the README,
license and notices. Dependencies obtained separately keep their upstream terms.
The repository is public, and private vulnerability reporting is enabled.

## Guest binary releases

The [guest-2026-09-22 release](https://github.com/Anharmoniclabs/BULL/releases/tag/guest-2026-09-22)
supplies `guest-2026-09-22-source-materials.tar.gz`, `SOURCE_SHA256SUMS` and
`SOURCE_REVIEW.json` alongside the unchanged image assets. Verify both checksum
files: the original `SHA256SUMS` covers the image delivery; `SOURCE_SHA256SUMS`
covers the source delivery added on September 23.

The bundle contains pinned BULL, Buildroot and qboot sources, target and host
manifests, source archives, patches, licenses, signed databases and build inputs.
All recorded inputs and both resolved configurations match the original build
record. All 67 package/version entries match the original build log. The sole
Buildroot warning (its own sources were not saved) is resolved by the included
Buildroot archive. Upstream prebuilt Rust host tools retain their bundled notices
and are identified as prebuilt tools, not compiler source archives.

These materials were reconstructed against the original records, not preserved
from its runner. This is not a claim of a bit-identical rebuild. See the bundle's
README and review record for reconstruction details and rebuilding instructions.

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

## Python release artifacts

Install the test extra and build requirements (`setuptools>=77` and `wheel`), then
run `python tools/check_package.py --output /absolute/new/package-check`.
It builds only committed source, creates a source distribution, builds its wheel,
checks license metadata, and installs that wheel in a fresh environment outside
the checkout. The output contains artifacts, checksums and the tested commit.
The Python distribution provides the library and CLI; the complete Git source
archive also supplies deployment tools, guest recipes and documentation.

`tools/release_check.py` includes this check and rejects a dirty or changed source
tree. A release candidate additionally needs CI and deployment/KVM evidence for
its exact commit and pinned images. Hardware approval is a separate gate; a
diagnostic USB device cannot satisfy it.
