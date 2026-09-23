# BULL II — revised evidence edition

Native LaTeX technical report by Luis Minier / Anharmoniclabs, September 23,
2026, revision 2. The latest **tested runtime is `ab53f56`**. This paper's Git
commit publishes those retained results; it is not a new live deployment run.

The manuscript replaces the preceding Paper II's stale 489-test/current-hardware
description with source-attributed 501 + 21 results, witnessed unsigned BOOT
gestures, bounded USB stale-response handling, and one-shot channel hardening.
Historical timings, Qwen results, failed attempts and unfinished hardware
acceptance remain explicit. The paper does not claim a secure signing token.

## Read and reproduce

The generated PDF, companion ZIP and publication manifest live in
`site/assets/papers/bull-ii*`. The website links them directly. Paper I's existing
PDF and manifest are retained separately. The companion is self-contained for
paper reconstruction, with reviewed evidence and figures; it is not a complete
BULL source distribution or a private audit-log export.

Install Python 3.12+ for the pinned paper dependencies (tested with 3.14.7),
a working TeX Live/pdfLaTeX installation (article,
fontenc, lmodern, geometry, graphicx, booktabs, longtable, tabularx, array, amsmath,
xcolor, url and hyperref), Cairo, and fonts used by the SVGs. On Debian/Ubuntu,
the usual TeX packages are texlive-latex-base, texlive-latex-recommended and
texlive-latex-extra; CairoSVG also needs the system Cairo library. Then:

```sh
python3 -m venv /tmp/bull-paper-venv
/tmp/bull-paper-venv/bin/pip install -r docs/papers/bull-ii/requirements.txt
/tmp/bull-paper-venv/bin/python docs/papers/bull-ii/build.py \
  --output /tmp/bull-paper-r2
```

The output directory must be new. To use a non-PATH TeX installation, pass
`--latex /absolute/path/to/pdflatex`. From an extracted companion, run
`python build.py --output /absolute/new/directory` in its `bull-ii` directory.
No Git history, network measurements, model, KVM, USB token or private keys are
needed to typeset it. Dependencies must already be available for an offline
build. Font/rendering/library differences may change PDF bytes; the checked-in
manifest identifies the actual published bytes and build engine.

Verify the published artifacts using Python 3.11+ and its standard library only:

```sh
python3 docs/papers/bull-ii/build.py \
  --verify-publication site/assets/papers
```

The build verifies archived input hashes, produces tables from CSV/JSON,
renders the milestone plot and original SVGs, runs LaTeX three times with
shell escape disabled, rejects unresolved references/layout overflow, and
packages source, evidence, generated tables/figures, PDF and SHA256SUMS.
The manifest links every source file and both generated artifacts by hash.
The Pages workflow checks these identities before publication.

## Evidence and privacy

`evidence-manifest.json` records source identity and SHA-256 for each archived
input. `coverage.json` maps the paper's result families and remaining limits.
`evidence/validation-ab53f56.json` is the reviewed release-candidate summary,
with unnecessary Cloudflare account dashboard URLs removed and their build
outcomes retained. No raw credentials, raw ledgers, private deployment state,
USB serials, model weights, VM images or private audit archive are included.

The copied historical documents are snapshots, including their dated blocked
states, paths and limitations. They are not current setup instructions. The
manuscript explains where later evidence supersedes a historical status.
Historical model actions used the host sandbox. No physical signature was
produced. Full offline guest recompilation remains unrun.

## Zenodo

The previous Paper II PDF is deposited at DOI 10.5281/zenodo.22922278; its hash
is in the evidence manifest. This rewritten PDF has **not** been uploaded to
Zenodo. Publishing these Git artifacts does not modify that deposit. For a
future Zenodo version, upload the new PDF **and companion ZIP**, cite this
documentation commit and the separate tested runtime, and verify the downloaded
files against `bull-ii-manifest.json`. Do not silently attribute the old DOI's
PDF hash or experiments to this revision.

Original paper source and scripts follow the included GPL-2.0-or-later LICENSE.
Original repository drawings retain the same project attribution. External
papers are cited, not bundled; dependency licenses remain their own.
