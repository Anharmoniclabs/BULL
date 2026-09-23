# Third-party materials

BULL's original source uses GPL-2.0-or-later (see LICENSE). This does not relicense
third-party dependencies, media, model weights or operating-system components.
No third-party Python packages or guest images are vendored in the Git tree.

## Python and tooling

The core package uses Python's standard library. CPython has its own
[PSF license and incorporated notices](https://docs.python.org/3/license.html).
Installed development metadata reviewed on 2026-09-23 records:

| Package | Reviewed version | Declared license | Role |
|---|---|---|---|
| pytest | 9.1.1 | MIT | Tests |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause | Test credentials |
| setuptools | 84.0.0 | MIT | Packaging |
| wheel | 0.48.0 | MIT | Packaging |
| build | 1.6.1 | MIT | Source distribution and wheel validation |

Version ranges in pyproject.toml permit other versions. These are direct tools,
not an exhaustive dependency SBOM. Redistributors must retain the notices for
the actual dependency versions they bundle. Installing from package repositories
does not add those packages to BULL's source license.

The collector's Wrangler tool is an external Cloudflare development dependency;
consult [its source and license](https://github.com/cloudflare/workers-sdk).
TLA+ tools, OpenSSH, OpenSSL, libseccomp, util-linux, QEMU, ClamAV and the system
build toolchain are external dependencies with their own notices.

## Guest images

A generated root filesystem bundles separately licensed packages, including Linux,
Python, Bash, ClamAV and libraries selected by Buildroot. Use the **actual build's**
legal-info manifests, license texts, corresponding sources, patches and configs;
this short inventory cannot substitute for them. Qboot is built separately and
must have its source and license included too. See [DISTRIBUTION.md](docs/DISTRIBUTION.md).

## Presentation assets

The paper is the user-supplied author-review manuscript by Luis Minier, published
without modification; [its manifest](site/assets/papers/manifest.json) records
provenance and hash. It is not peer-reviewed.

The externally hosted explainer uses synthetic Piper `en_US-libritts-high`
narration, speaker 0. The [voice model card](https://huggingface.co/rhasspy/piper-voices/blob/main/en/en_US/libritts/high/MODEL_CARD)
identifies [LibriTTS](https://www.openslr.org/60/) by Heiga Zen and collaborators
and its [CC BY 4.0 license](https://creativecommons.org/licenses/by/4.0/).
The project synthesized narration for this video; the voice is not presented as
a named person's recording or endorsement. Attribution is also retained in the
[media manifest](site/assets/explainer/manifest.json). Model weights, rendering
tools and video bytes are not bundled in this repository.

A model's license is separate from BULL's. Operators obtain their own local model
and check its terms; the Qwen test result does not grant rights to model weights.
