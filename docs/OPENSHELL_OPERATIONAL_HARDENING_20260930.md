# BULL × OpenShell operational hardening — 30 September 2026

This change extends the existing OpenShell experiment at `20a42c807214f47c2b5d6521089485cee0898017`. It retains the fail-closed composition boundary and adds bounded decisions, live revocation, persistent request identity/replay rejection, and a verified-head append path. It does not qualify the composed system as production-ready.

## Added behavior

| Workstream | Implemented behavior | Qualification boundary |
| --- | --- | --- |
| Partial failures | Configurable 250 ms default decision budget, shorter caller deadlines, explicit timeout/unavailable/backpressure denials, bounded worker slots, and an advertised middleware deadline. Late workers cannot send ALLOW to the expired caller. | Real BULL gRPC and local HTTP effects; native NVIDIA gateway rerun remains pending. Hung workers require operational recovery; no automatic failover was added. |
| Dynamic revocation | Signed optional parent grant relationships; child authority must be a subset. Revocation removes specified capabilities and advances epochs through the subtree. State survives restart. A policy evaluation that observes an epoch change is denied. Old action approvals bind the old epoch. | Applies to this adapter's signed sandbox-grant graph. Other BULL registries, already running processes, distributed brokers, and effects admitted before revocation need separate integration. |
| Audit append | One full startup/history scan, then reuse the verified head under process/thread locks while the ledger and checkpoints retain their expected identities. Atomic, synced head writes; authenticated checkpoint support. Descriptor identity and exact byte growth are checked before trusting the completed append. | O(1) history work for a steady, persistent single writer and bounded record size. Startup, forensic verification, and switching independently cached writer instances remain O(n). |
| Exact attribution | Boundary-generated 128-bit request and decision IDs; digest binds sandbox, target, method, body hash and request ID. Reserved headers are overwritten. SQLite retains upstream request claims across restart and denies duplicate delivery. Exact JSONL joining rejects missing, duplicate or mismatched identities. | Native OpenShell shorthand still lacks these fields. The exporter preserving middleware metadata has not been implemented or tested here. IDs alone are not cryptographic authentication. |

`REVOKE_NEXT_EFFECT` allows computation to continue but removes the revoked authority at subsequent checks. `REVOKE_TERMINATE` requires a trusted termination hook and first removes all capabilities from the affected subtree. The server's administrator command provides normal revocation; real process termination and credential cleanup are not claimed.

Replay rejection is scoped to the trusted supervisor's `(sandbox_id, request_id)`, not to every future identical HTTP payload. A fresh supervisor request is a new attempt. The persistent table fails closed at 100,000 entries; safe rotation/retention is an open operational task. Unauthenticated middleware transport remains an open production boundary.

## Validation

The focused operational, adapter, audit integrity, storage recovery and anchor suite passes **85 tests**, including three checkpoint-window mutation cases. The real gRPC fault harness checks 10/50/100/250/1000/5000 ms delays, reset exceptions, duplicate delivery, a shorter client deadline, and authority unavailability while observing a real loopback destination.

The identical-request workload uses **10,000 requests with 32 clients in flight**, not 10,000 simultaneously active clients. It exercises real BULL gRPC, a real HTTP destination, and an explicitly labelled OpenShell policy-layer fixture. Native OpenShell OCSF evidence is not substituted by that fixture.

The first million-record run failed final verification: it contained missing record ranges. Its latency measurements are rejected as qualified scaling evidence. Investigation exposed an append-cache gap: a file changed during checkpoint publication could be adopted as valid. Regression tests now reproduce truncation, replacement, and same-size modification in that window. The source of the original missing-range writes was not identified; the corrected run is required before accepting scaling results. Both runs must be retained in the evidence bundle.

The broad source suite has five failures on this host: four unavailable Unix socket operations and one unavailable namespace/backend attestation case. The unchanged experiment base reproduces the same five failures. Missing protections remain failures, not simulated passes. Four pre-existing checks are skipped. Codespaces must rerun the full suite on its actual host.

## Codespaces

Use an isolated worktree so existing running work and uncommitted changes are preserved:

```bash
git fetch origin hardening/openshell-operational-20260930
BULL_TEST_WORKTREE="$(mktemp -d /tmp/bull-operational-source-XXXXXX)"
git worktree add --detach "$BULL_TEST_WORKTREE" FETCH_HEAD
bash "$BULL_TEST_WORKTREE/tools/run_codespace_openshell_operational.sh"
```

If the script does not discover the already-built pinned NVIDIA/OpenShell source, rerun with `--os-src /absolute/path/to/OpenShell`. `--quick` skips the million-record scaling test while preserving the 10,000-request and fault tests. The runner needs Docker plus the four built binaries listed by its preflight, from NVIDIA/OpenShell v0.1.2 commit `6648bd0c290efbc41ba131ee9831ee45cd431f94`.

The script writes a summary JSON, regression XML/log, loopback evidence, and native results when prerequisites exist. Its native runner uses a disposable gateway/database and deletes only sandboxes created by that gateway. Missing native prerequisites produce **BLOCKED** and exit code 2. The original composition experiment now returns nonzero when its cases fail.

## Remaining qualification

- Native NVIDIA/OpenShell Docker delay/reset/restart/revocation checks and the original A/B composition rerun.
- Native JSONL/OCSF export with trusted identity fields and a 10,000-request exact native join.
- mTLS or an equivalently authenticated middleware channel and sandbox identity binding.
- Distributed revocation, credential invalidation, and real emergency termination hooks.
- Multi-process append performance, segmented verification, remote collector latency and recovery, and storage fault/crash campaigns.
- Approval/control-state transactional semantics across cancellation, crash and post-commit reconciliation.
- Replay-state retention, hung-worker watchdogs, bounded service ingress queues, health monitoring and failover without bypass.

This is experimental engineering evidence, not formal verification, universal prompt-injection protection, or independent certification.
