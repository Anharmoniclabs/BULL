# BULL engineering website

The public site is a static architecture publication with an embedded narrated data-flow film, implementation diagrams, source links, a generated tracked-file inventory and commit-specific CI evidence.

There is no public policy evaluator, request editor, model endpoint form, browser Python runtime or testing console. Their source files have been removed from the current tree. Backend regression tests remain under `tests/`.

Build locally from the repository root:

```sh
python3 tools/build_site.py --output _site
python3 -m http.server 8000 --directory _site
```

The source template uses `data-code` references. The build resolves these to commit-specific repository links and generates the source inventory. Run `python3 -m unittest discover -s tests -p test_brand_site.py -v` for static contracts. These tests do not certify a workload or boot a VM.

The film is rendered through the Higgsfield media sandbox with deterministic motion graphics and synthesized narration. It is illustrative, not a recording of a production VM. The media manifest records the inspected source revision, caption/transcript provenance and content hash. Video bytes live in the owner's Higgsfield media storage; the repository stores documentation, captions and provenance, not a large video or VM image.

Brand assets are used as the header identity and favicon, not presented as a visitor-facing logo gallery. Local deployment assets remain excluded by the repository artifact policy.

## Cloudflare website mirror

The root `wrangler.jsonc` configures the `bull` static website Worker with `site/`
assets, preserving the settings in the operator's successful main build at
`974eb17`. That build ran `npx wrangler deploy`, which generated a configuration.
Failed branch builds ran `npx wrangler versions upload` without a configuration.
The checked-in configuration makes asset selection explicit for both commands.

Keep build root `/`, no build command, and production branch `main`. The
production command is `npx wrangler deploy`. Cloudflare's Worker Previews build
uses `npx wrangler preview`; the root configuration includes the required empty
`previews` block. Assets and compatibility settings remain at the top level.
This is distinct from the older `npx wrangler versions upload` workflow, which
uploads an unpromoted version. Do not change dashboard commands to work around
a missing preview configuration. See the official
[preview configuration](https://developers.cloudflare.com/workers/previews/configuration/).
Validate locally without uploading with
`npx wrangler deploy --dry-run --config wrangler.jsonc`.

This mirror serves checked-in templates directly, matching the existing
deployment. The generated publication described above resolves source links and
adds inventory/transcript pages; switching the mirror to that output is a
separate publishing change.

The audit collector is the separate `bull-audit` Worker configured under
`deploy/cloudflare-audit/`. Keep both repository connections. Do not point the
website at the collector configuration or move its database bindings or secrets
to fix a website build failure.
