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

The first million-record run failed final verification: it contained missing record ranges. Its latency measurements are rejected as qualified scaling evidence. Investigation exposed an append-cache gap: a file changed during checkpoint publication could be adopted as valid. Regression tests now reproduce truncation, replacement, and same-size modification in that window. The source of the original missing-range writes was not identified; the corrected run is required before accepting scaling results. Both runs are retained in the evidence bundle. The corrected run passes final verification for exactly **1,000,000 records** (head `19aa5ff1c7d633d2c1f9c1ea1f94b031c98582b8f248c1290f78fd6104945091`); the forensic full scan takes 5.79 s. Append medians below use the final 300 appends at each size, real fsync and an authenticated local checkpoint.

| Existing workload size | Append p50 (ms) | Append p95 (ms) | Full scans during append |
| --- | ---: | ---: | ---: |
| 1,000 | 0.353 | 0.664 | 1 |
| 10,000 | 0.382 | 0.782 | 1 |
| 100,000 | 0.346 | 0.520 | 1 |
| 1,000,000 | 0.396 | 0.700 | 1 |

The corrected run also observes 10,000 distinct destination effects and a complete exact fixture join with zero missing/duplicate identities, unmatched effects, or orphan events. All 11 real gRPC fault cases pass. These observations support flat steady-writer history work on this host; they do not establish distributed scaling or native OpenShell identity export.

The broad source suite has **1,063 passes, 21 passing subtests, 4 skips, and five failures** on this host: four unavailable Unix socket operations and one unavailable namespace/backend attestation case. The unchanged experiment base reproduces the same five failures. Missing protections remain failures, not simulated passes. Four pre-existing checks are skipped. Codespaces must rerun the full suite on its actual host.

## Codespaces

Run this from **any directory**, including `~/.local/share/bull/command-center`.
That directory holds runtime data, not the Git checkout. The following command
clones an isolated source tree and saves logs under your home directory:

```bash
bash <<'BULL_QUALIFY'
set -euo pipefail
mkdir -p "$HOME/bull-test-results"
BULL_RUN_DIR="$(mktemp -d "$HOME/bull-test-results/openshell-XXXXXX")"
git clone --single-branch --branch hardening/openshell-operational-20260930 \
  https://github.com/Anharmoniclabs/BULL.git "$BULL_RUN_DIR/source"
bash "$BULL_RUN_DIR/source/tools/run_codespace_openshell_operational.sh" \
  --output "$BULL_RUN_DIR/results" --push-results
BULL_QUALIFY
```

If the script does not discover the already-built pinned NVIDIA/OpenShell source,
add `--os-src /absolute/path/to/OpenShell` to the runner invocation. `--quick`
skips the million-record scaling test while preserving the 10,000-request and fault
tests. Native tests need a reachable Docker daemon plus the four built binaries
listed by preflight, from NVIDIA/OpenShell v0.1.2 commit
`6648bd0c290efbc41ba131ee9831ee45cd431f94`. The runner checks prerequisites but
does not install Docker or build OpenShell. A CLI installation alone is insufficient.

The script prints a Markdown terminal table with PASS, FAIL, BLOCKED, NOT_RUN and
OPEN rows, and writes `SUMMARY.md`, `summary.csv`, `summary.json`, `terminal.log`,
individual phase logs, regression XML, loopback evidence, and native results when
prerequisites exist. Quiet phases emit a heartbeat every 15 seconds. Setup failures
are finalized too; zero exit codes without required result files are failures.
Existing output folders are rejected to prevent stale results being reused.

`--push-results` commits compact reports and a SHA-256 manifest to a unique
`results/openshell-<UTC timestamp>-<run id>` branch using a separate publishing
worktree. Failures and BLOCKED results are published too. The terminal prints the
GitHub results URL. The source branch, main, and the running checkout remain
unchanged. Raw logs, large ledgers, private keys, gateway configuration and SQLite
state remain local; publication uses an explicit file allowlist. A clean source
checkout is required to bind evidence to the recorded tested commit. GitHub write
authentication is required; a rejected push retains its evidence commit and prints
the exact retry command. `publication.json` records push status locally.

Its native runner uses a disposable gateway/database and deletes only sandboxes
created by that gateway. Missing native prerequisites produce **BLOCKED** and exit
code 2 unless another stage failed, in which case the run exits 1. A completed
tested scope exits 0 while still listing unqualified OPEN boundaries. The original
composition experiment returns nonzero when its cases fail. None of these runs
claims native OCSF export, authenticated transport, distributed revocation,
emergency credential cleanup, multi-process scaling or watchdog failover.

## Branch integration audit

All **86 pre-existing remote branch snapshots** passed Python syntax checks (680 unique Python blobs). Ancestry alone undercounts integrated work because many older PRs were squash-merged. The read-only inventory records current tips, ancestry, patch identity, PR state, and files absent from the candidate.

| Audit category | Branches |
| --- | ---: |
| Directly contained in main | 11 |
| Historically merged; tip/tree drift needs consideration | 42 |
| Contained in this consolidated release candidate | 7 |
| Patch-equivalent to candidate | 1 |
| Open distinct or superseded work | 10 |
| Historical branch needing file-level disposition | 15 |

This candidate contains the production-validation/MCP release proposal and the OpenShell experiment. Distinct Kaggle/harness, older UI, legal, honeypot and paper branches were not indiscriminately merged, deleted, or certified. Draft PR #90 targets main; default-branch release, native host checks, signatures and other required gates remain pending.

## Remaining qualification

- Native NVIDIA/OpenShell Docker delay/reset/restart/revocation checks and the original A/B composition rerun.
- Native JSONL/OCSF export with trusted identity fields and a 10,000-request exact native join.
- mTLS or an equivalently authenticated middleware channel and sandbox identity binding.
- Distributed revocation, credential invalidation, and real emergency termination hooks.
- Multi-process append performance, segmented verification, remote collector latency and recovery, and storage fault/crash campaigns.
- Approval/control-state transactional semantics across cancellation, crash and post-commit reconciliation.
- Replay-state retention, hung-worker watchdogs, bounded service ingress queues, health monitoring and failover without bypass.

This is experimental engineering evidence, not formal verification, universal prompt-injection protection, or independent certification.
