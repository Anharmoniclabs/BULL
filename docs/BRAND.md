# BULL brand assets

BULL means **Blocking Unauthorized Logic Loopholes**. The approved bulldog integrates a capital **B** into the left side of its silhouette. It is the shared identity for the project, website and documentation—not a public logo-gallery section.

## Approved source of truth

The owner's approved image is preserved **byte for byte** at [`site/assets/brand/bull-approved-sheet.png`](../site/assets/brand/bull-approved-sheet.png), including all four presentation panels. It is 1448 × 1086 pixels. Its SHA-256 is:

```text
79a75d93e09f2b0a460c7ae3feb854c601803adc922bf9a54346955bfd7d803a
```

The SVGs are self-contained, two-tone vector adaptations traced from that exact image. They preserve the approved B-shaped bulldog and its supplied lettering; they are not original designer vector masters. Small antialiasing and texture differences from the raster are expected. No image embeds, external fonts or font files are needed by the SVGs. The original source and unaltered mark/primary raster crops remain available alongside them.

| Asset | Use |
|---|---|
| `bull-approved-sheet.png` | Exact approved four-panel source image |
| `bull-mark.svg` | Project mark and website footer |
| `bull-primary.svg` | Website header, generated documentation headers and light-background README |
| `bull-primary-dark.svg` | Dark-background README |
| `bull-stacked.svg` | Stacked composition for square placements |
| `bull-one-color.svg` | Single-ink adaptation with white knockout details |
| `bull-favicon.svg` | Browser tab; simplified to one ink |
| `bull-mark.png`, `bull-primary.png` | Direct crops of the original raster, with no redrawing |
| `manifest.json` | Approved-source identity and exact content hashes of all variants |

The existing project and Pages references use these stable filenames. Updating this pack updates the README, homepage header and footer, browser tab, repository inventory page header, and transcript page header without changing the security runtime or the architecture film.

Preserve proportions and a clear margin. Do not add horns, shields, neon effects or unrelated symbols. Use the mark alone when the descriptor would be unreadable. Charcoal is `#202830`; silver is `#8c98a4`. The dark-background variant is intended for a dark README surface.

## Rebuilding and checking

Only maintainers rebuilding artwork need the extra image tools. The normal Pages build uses the committed assets directly and does not download artwork or install a vectorizer.

```sh
python -m pip install Pillow==11.3.0 vtracer==0.6.12
python tools/build_brand_assets.py
python -m unittest discover -s tests -p test_approved_brand.py -v
python -m unittest discover -s tests -p test_brand_site.py -v
```

The generator refuses any input whose SHA-256 does not match the approved source. An intentional future rebrand requires a separately approved source, updated generator and tests, and a reviewed manifest.

## Publication scope

The public website remains a static engineering publication with the existing narrated architecture film, captions and transcript. It does not display a logo-download gallery or a visitor testing console. Source variants remain available to maintainers in Git.

Branding PNGs and SVGs are public project assets. **Guest disk images**, kernels, credentials and real deployment configurations are not branding assets and still belong outside the checkout. The local-only VM protections remain unchanged.

## Naming and technical claims

Use BULL consistently. Tie implementation statements to source. Distinguish architectural illustrations from live execution, host regression tests from real-KVM boot evidence, and bounded formal models from implementation-wide proofs. Do not imply independent certification or a finished persistent MicroVM release.
