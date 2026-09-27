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

## Downloaded release evidence and trust

`--release-dir` alone checks the inventory and document structure. It cannot
turn a downloaded `attestation-verification.json` into proof: that file is only
an untrusted historical claim. `SUPPLY.ATTESTATION_VERIFIED` stays `BLOCKED` and
`release_complete` stays false until fresh cryptographic verification succeeds.

```bash
bull assurance status --release-dir /private/release \
  --expected-source FULL_TRUSTED_40_CHARACTER_COMMIT_SHA
```

Obtain the expected commit through a trusted source, not from the same downloaded
verification record. This command requires a trusted `gh` installation and its
Sigstore trust material; it may need network access. It verifies the supplied
bundles, pins `Anharmoniclabs/BULL` and `.github/workflows/guest-release.yml`, pins
the source commit, denies self-hosted signers, checks every provenance subject,
and binds the CycloneDX predicate and SBOM contents to `rootfs.ext4`. Missing
verifiers, failures, empty output and timeouts fail closed. This validates
provenance, not the safety or license completeness of the attested software.

Use a private, host-owned staging directory. Inspection does not install files,
make the directory immutable, or eliminate an adversarial concurrent writer.
Checksum files provide integrity comparisons, not independent authenticity.
`source_complete` means required source controls are registered; it does not
mean tests ran or passed. Conditional human approval must be configured for
protected broker effects even when the required deployment subset passes.

Integrity manifests generated before the assurance hardening change must be
regenerated and signed by the trusted operator: assurance code and its packaged
registry are now required manifest subjects. Do not disable integrity checks to
reuse an old manifest.

Verifier flag semantics follow the [GitHub CLI attestation verification manual](https://cli.github.com/manual/gh_attestation_verify).
