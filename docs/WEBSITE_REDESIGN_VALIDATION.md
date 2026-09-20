# Website redesign validation

Branch: `design/bull-premium-site-v2`; base: `01cd259`.

## Delivered

- Editorial hero, scoped evidence strip, architecture overview, authority lineage,
  defense stack, nested MicroVM illustration, benchmark class index, external
  checkpoint route, manuscript section and prominent limitations.
- All existing long-form sections, source mapping, captions, video and raw evidence retained.
- Supplied 10-page PDF copied unchanged, with SHA-256 provenance manifest.
- Responsive CSS breakpoints, keyboard-scrollable tables, focus states and reduced-motion handling.
- No paid generation services, external fonts or additional animation dependencies.

## Executed checks

- Python compileall: passed.
- JavaScript syntax: passed.
- Static site build: passed.
- Existing publication contracts: **17 passed**.
- Full suite in this workspace: **268 passed, 4 failed, 6 subtests passed,
  15 warnings**. Three failures were AF_UNIX socket creation denied by the
  environment; one sandbox test returned no bootstrap attestation. No runtime
  source or tests were modified. Hosted CI is still required.
- Benchmark data and chart files: unchanged. Exactly one `id="benchmarks"`.
- Git whitespace check: passed.

## Outstanding review gate

Cloud Browser rejected local HTTP preview access. A subsequent offline URL
check was rejected by its protocol policy; no workaround was attempted.
Consequently, desktop/mobile screenshots, six-width overflow checks and the
requested two visual refinement passes are **not complete**. CSS breakpoints
are implemented, but this is not a claim of rendered responsive validation.
The YouTube page loaded without reliable design video frames; fidelity to the
reference is not established. Written design instructions were used.

Keep the PR draft until rendered review and the full hosted checks pass.
Do not bypass branch protection or publish to main before those gates pass.
