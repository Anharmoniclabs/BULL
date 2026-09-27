# Session reuse, output publication, and host trust

Status: design requirements, not implemented feature claims. The shipped guest
supervisor remains one-shot and input disks remain read-only. Control-channel
hardening rejects a second execute and prevents reuse after protocol failure.
These checks do not establish persistent guest isolation or writable exports.

## Host compromise

Ordinary KVM assumes a trusted host administrator and hypervisor. Guest-held
keys and guest reports cannot establish independence from an administrator
who can inspect or alter that guest. An external authenticated checkpoint
provides a separate record, not proof of trustworthy computation on a
compromised host holding the authentication key.

A separate confidential-computing deployment would need supported SEV-SNP or
TDX hardware, patched firmware, verified fresh hardware attestation bound to
an ephemeral guest key, an independent verifier with approved measurements,
and secret release only over that attested channel. The host must not receive
those secrets. Persistent data additionally requires rollback detection using
state outside the hostile host. This is not implemented by BULL's current
nonce-bound sandbox bootstrap. Availability, all physical attacks, and all
side channels are not guaranteed by confidential computing.

Primary references:
- https://www.amd.com/en/developer/sev.html
- https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
- https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3024.html

## Persistent guest acceptance requirements

Do not implement reuse by looping over the current immutable one-command grant.
Introduce explicit session lifecycle, unique per-action identifiers and narrow
fresh authority with expiry. Bind requests and results to session, action,
workspace generation and approved content. Serialize dispatch. Require new
sandbox scopes, no inherited descriptors or credentials, verified descendant
cleanup, storage budgets and externally anchored completion before another
operation. Any uncertain cleanup or protocol failure destroys the guest.
Never reuse a guest across trust tenants. Recovery must reconcile externally
committed action state; an ambiguous consequential operation cannot be blindly
retried. Persistent reuse remains disabled until real KVM tests cover these
requirements, including crashes at each lifecycle transition.

## Writable output acceptance requirements

Never mount a writable host workspace into the guest. Use guest-private bounded
scratch. Transfer bounded output bytes to a host quarantine through a narrow
protocol; do not mount an attacker-created filesystem on the host for export.
Only regular files and explicitly supported directories are eligible. Reject
absolute/traversal paths, links, devices, special files, excessive sizes/counts,
and metadata capable of granting privilege. Normalize modes.

Bind review/approval to an immutable output manifest, exact target and expected
base generation. Apply any required scanning to those same bytes. Use a trusted
host-owned export parent, descriptor-relative constrained operations, and
no-clobber publication of a new version. Existing-workspace replacement needs
an additional transactional design, stale-base rejection and crash reconciliation.
An audit failure must not cause a repeated publication. Output content remains
untrusted even after safe transfer and must not automatically be executed.

Required tests include path/link races, malformed and oversized streams, changed
content after approval, stale base, duplicate action, interrupted transfer,
interrupted publication and audit outage. Real guest-to-host integration is
required in addition to unit tests before enabling this feature.

## Validation of this hardening change

Base: 437de3fd03da2e8d8ca15e7bcb9804e45317b58a.
Python 3.12 local targeted protocol suite: 12 passed.
Full pytest run: 488 passed, 21 subtests passed, 4 failed. The identical four
failures reproduced on an untouched base checkout: three AF_UNIX creation
PermissionErrors and one missing namespace backend attestation. These failures
remain failures; they were not skipped or counted as passes. This execution
environment has no /dev/kvm, so no real VM or confidential-computing test ran.
