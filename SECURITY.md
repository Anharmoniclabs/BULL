# Security policy

BULL is security-sensitive infrastructure. Please treat suspected bypasses, sandbox escapes, capability-confusion bugs, secret/egress authorization failures, audit-integrity failures, and scan-to-execute inconsistencies as security issues.

## Supported security target

The actively maintained target is the current `main` branch and the production profile described in `docs/PRODUCTION_SECURITY.md`.

## Reporting

For public-safe issues, open a GitHub issue with the smallest reproducible case. Do not include live credentials, private keys, tokens, personal data, or exploit traffic targeting third-party systems.

For sensitive vulnerabilities, use [GitHub private vulnerability reporting](https://github.com/Anharmoniclabs/BULL/security/advisories/new), enabled for this repository. Do not publish exploit details or credentials in an issue while a private report is being reviewed. No response-time SLA or independent certification is promised.

A useful report includes:

- affected commit SHA
- relevant BULL mode/profile
- minimal reproduction
- expected vs actual authority decision
- whether the issue crosses a sandbox, capability, domain, secret, egress, audit, or integrity boundary
- whether the behavior reproduces with the current security regression suite

## Security claims

Passing CI, TLA+ model checking, host certification, or adversarial tests does not prove the entire Python/Linux implementation is vulnerability-free. Security claims should be limited to the documented threat model and tested invariants.

## Credentialed approval candidate

Approval reuse, mismatched-action acceptance, credential substitution, missing
presence/verification acceptance, state rollback exposure, and unmediated broker
access are security-relevant. The gate trusts host-controlled credential enrollment,
policy, durable state and operator UI. See [claims](docs/SECURITY_CLAIMS.md) and
[human approval](docs/HUMAN_APPROVAL.md) for implemented scope and exclusions.
