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
