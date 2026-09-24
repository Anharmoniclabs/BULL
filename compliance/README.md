# BULL assurance control registry

This directory documents the machine-enforced assurance architecture.

The authoritative machine-readable registry is packaged at
`src/bulldog/data/assurance_controls.json`. It intentionally separates:

- **source controls** — implemented code/test properties, reported as
  `IMPLEMENTED`, not as live runtime proof;
- **deployment controls** — configuration or live-host properties that can report
  `PASS`, `FAIL`, or `BLOCKED`;
- **release controls** — SBOM/provenance/signature/verification evidence produced
  by the release workflow;
- **external controls** — organizational, legal, assessor, or validated-module
  requirements that BULL must never self-certify.

Use:

```bash
bull assurance status
bull assurance status --dynamic
bull assurance status --dynamic --json /private/report.json
bull assurance status --release-dir /path/to/release
bull assurance status --dynamic --require-complete
```

`--dynamic` launches the real namespace backend through the existing host
certification path. Missing protections remain `BLOCKED` or `FAIL`; the command
does not replace unavailable hardware or deployment evidence with simulated
success.

The assurance report always contains `"certified": false`. External
certifications and legal conformity require their own evidence and authority.

`COMPLIANCE.md` is the human-readable standards crosswalk. It should describe
what the registry and evidence prove; it is not the source of enforcement.
