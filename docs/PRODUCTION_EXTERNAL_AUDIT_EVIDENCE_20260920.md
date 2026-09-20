# External production audit-anchor evidence — 2026-09-20

This note records operator-supplied deployment evidence for the BULL production audit path. It is **not** an independent security audit.

## Observed production-host results

The Linux host production gate reported `PRODUCTION BOUNDARY: PASS` with strict seccomp, signed integrity and policy state, private snapshot/audit paths, delegated cgroup v2 state, a fresh audit session and non-local HTTPS transport.

The external collector was a Cloudflare Workers + D1 deployment implementing BULL's authenticated checkpoint protocol. No deployment key is committed here.

## Edge compatibility finding

Cloudflare blocked Python urllib's default client signature before the Worker with error 1010. An explicit `User-Agent: BULL-AuditAnchor/1` reached the Worker. BULL's HTTPS transport was updated in commit `cd461ae05a0925d6bd32381f8ef4da9e99bb2ccb`.

## Recovery and final checkpoint

A failed delivery had committed one local ledger record without the matching `.remote` checkpoint, and BULL refused a new append. The operator used `AuditLedger.reconcile_remote()`: local-only verification passed with 1 record, reconciliation passed, normal local+remote verification passed, a fresh authenticated append passed, and final verification passed with 2 records.

This demonstrated fail-closed interruption handling, explicit remote-checkpoint reconciliation without replaying workload execution, a fresh authenticated checkpoint, an authenticated acknowledgement and a valid final local ledger.

## Limits

This concerns one operator-controlled host and one external collector deployment. It does not establish protection from a malicious host administrator, compromised kernel/hypervisor, external-account compromise, unknown defects or attacks outside the executed corpus.
