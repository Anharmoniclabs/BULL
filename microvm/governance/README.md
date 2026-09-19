# Protected merge rollout

`main-ruleset.json` is the intended solo-maintainer ruleset. Apply only after
the named jobs exist on main and a GitHub squash merge has been verified to
produce a signed commit. It requires PRs and resolved conversations, with zero
required approving reviewers, verified signatures, required checks, and no
force pushes or branch deletion. There are no bypass actors.

The GitHub Actions integration ID is 15368. Match check contexts against actual
runs before applying. Add the real KVM integration job only after it exists and
has demonstrated a boot on its runner; a preflight or mocked test does not
qualify. Do not silently omit KVM from the eventual production release gate.

Existing unsigned history is preserved. Do not rewrite it to establish signed
merges. Verify the squash merge commit's GitHub `verification.verified` result
before requiring signatures. A checked-out local unsigned commit alone does
not demonstrate a verified-signature merge path.

CI action tags were resolved through the official GitHub repository APIs on
2026-09-19 and replaced with immutable commit SHAs. This pins the fetched
versions; it is not an independent audit of upstream action code. TLA+ v1.7.4
was downloaded from its official release, matched against the previous SHA-1
pin, and hashed with SHA-256:

```text
936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
```

For an asset update, review upstream changes, record the immutable version and
SHA-256, rebuild with an input inventory, run regressions and real KVM checks,
and publish evidence tied to the exact commit and image hashes. Retain the
previous verified release and its evidence for rollback. Do not substitute a
successful dependency download or a software-emulated boot for hardware tests.
