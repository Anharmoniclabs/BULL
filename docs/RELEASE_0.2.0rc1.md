# BULL 0.2.0rc1 release candidate

This is an experimental source candidate, not a security certification.

## Changes

- Integrates the four runtime hardening files from PR #46 without reverting the
  newer engineering website: canonicalization, socket filtering, namespace
  bootstrap and pre-execution attestation gate.
- Adds signed-policy configuration for a durable, expiring, one-use consequential
  broker approval. Approval never overrides existing capability/domain policy.
- Adds OpenSSH SK signature verification requiring signed presence and user
  verification, with a dedicated application and signature namespace.
- Adds operator export/sign/cancel CLI and a real-device ceremony check script.
- Integrates the gate into production secret retrieval and network request
  dispatch; signed exact routine GET/HEAD URLs continue without approval.
- Separates each egress request's formal trace lifecycle so a second authorized
  request does not report a trace failure after the HTTP effect.
- Adds approval modules and previously omitted directly used model/socket/egress
  modules to the trusted-computing-base integrity manifest.
- Adds cryptographic/state/dispatcher tests, an approval state-machine abstraction,
  test dependencies, and source-evidence collection with explicit deployment gaps.

## Compatibility and migration

Version changes from 0.1.0 to 0.2.0rc1. Regenerate signed integrity manifests and
rebuild pinned guest runtime images. Existing production policies without approval
configuration block protected broker operations. Read-only sandbox work does not
require a human approval credential. Private approval state and key handles must
remain outside all agent-accessible mounts. Deployment operators enroll their own
authenticator; no default credential or software-key fallback is included.

## Validation status

See `VALIDATION_20260922.md` for recorded local results. Required hosted CI must
pass on the final candidate commit. Synthetic security-key tests verify protocol
behavior, not hardware identity or human presence. Historical KVM evidence is
not reused as a pass for this changed runtime.

Release gates (local results are revision-specific; consult the validation record):

1. Real authenticator enrollment, physical ceremony and credential revocation.
2. Current-candidate live Linux production prerequisite checks; previously demonstrated locally.
3. Current-candidate real KVM cases with verified pinned assets; previously demonstrated locally.
4. A current guest action correlated with the actual external collector receipt; previously demonstrated locally.
5. Review of all agent adapters and operator-channel authentication.
6. Independent assessment before high-risk deployment.

No arbitrary host command, publishing, destructive-change, or security-change
adapter is introduced. Hardware attestation verification, trusted action displays,
writable workspace promotion and persistent VM reuse are not completed features.

## Reproduction

The [portable deployment workflow](REPRODUCIBLE_DEPLOYMENT.md) now creates
independent installation authority and supplies a public guest recipe without
the author's private baseline. `deployment_setup.py`, `host_setup.py` and
`deployment_check.py --deployment` replace the manual per-machine paste blocks.
The legacy `bull-production-provision.sh` entry point now forwards the new
`init/configure/show` interface; its old checkout-resetting CLI is retired.
Public recipe configuration is a separate CI check. Full public-image compilation,
boot qualification and bit-for-bit comparison are not established by that check.

Install the package and test extras in a dedicated Python environment:

```sh
python -m pip install -e '.[test]'
python tools/release_check.py --tla-jar /PRIVATE/tla2tools.jar --output /PRIVATE/new-source-evidence
```

The runner checks the jar against the pinned v1.7.4 SHA-256 from formal CI. Use a
fresh output directory outside Git. A missing prerequisite, failure or skipped
test is not a pass. Full output may contain private deployment paths; publish only
sanitized summaries. The runner does not silently provision keys, alter host
security configuration, launch external scans, or certify the deployment.

For checks in the current Codespace or deployment host, use
`tools/deployment_check.py`. It runs actual host and local TLS checks, probes KVM,
and invokes the existing guest and physical approval runners when their inputs
are available. The guest runner now supports an operator-selected external
collector and correlates its authenticated receipt with completion evidence.
See [Codespaces deployment checks](CODESPACES_DEPLOYMENT_CHECKS.md) for credentials,
pinned assets, physical interaction requirements and explicit BLOCKED results.
This wiring does not itself establish a live external/KVM or hardware pass.
