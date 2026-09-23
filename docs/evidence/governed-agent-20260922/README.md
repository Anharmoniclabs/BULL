# Governed-agent evidence published 2026-09-23

The 40 model-selected actions executed through **ProductionDispatcher and
ProductionRuntime into the host Linux NamespaceSandbox**. They did **not** execute
inside the MicroVM. The supervisor and Ollama server were trusted host processes.
The separate five KVM cases do not establish a model-driven VM loop.

## Source identities and distinct results

| Evidence | Source identity | Result |
|---|---|---|
| Historical local Qwen run | `974eb17081e3374e99ecd35f9ebb3ef6121beefa` plus uncommitted changes identified by [source-manifest.json](source-manifest.json) | 40 completed actions; 707.4835 seconds; two recovery events; one credential denial |
| Historical regression and offline reconstruction | Same baseline plus recorded source snapshot | 380 tests + 6 subtests passed, including reconstructed source |
| Fresh deployment from reconstructed source | Same recorded source snapshot | Two completed actions; two recovery events; one credential denial; 36.609 seconds |
| Earlier PR #55 validation | `da4f78675a52b1ed3020af319bd53696859770c3`; `d7053d3306fd53ea0691883dd71731b82d7b4b2c` has identical source | PR reports 408 tests + 6 subtests and five KVM cases with the existing external collector |
| Integrated agent implementation | `da10181dc954d9f90380f63e19cbaf98b2065171` | Local host regression: 430 tests + 6 subtests; zero failures or skips |

The historical run has no clean tested commit: its report explicitly records a
dirty worktree. Do not cite the baseline alone, the earlier PR candidate, or the
new publication commit as its exact tested source. The complete historical file
manifest matched the retained local checkout byte-for-byte during publication.
The manifest describes that historical snapshot, not the integrated PR tree.
The integrated regression ran on the same implementation bytes immediately
before commit. Live model, KVM, and deployment checks were not rerun for publication.

The initial integrated test run under the agent's restricted execution sandbox
reported 416 passes and 14 failures involving socket/namespace restrictions.
The host-permission rerun passed all 430 tests without changing code or disabling
protections. These are distinct runs, not combined counts.

## Model and recovery

Model: `qwen2.5:1.5b-instruct`.
Digest: `65ec06548149b04c096a120e4a6da9d4017ea809c91734ea5631e89f96ddc57b`.
Only `inspect` and `checksum` of the fixed fixture were available. The prompt
explicitly guided the next tool selection; this is bounded workflow evidence,
not a measure of general planning capability.

The dedicated worker exited with code 75 after persisting its plan, then code 76
after the read-only effect but before recording completion. The third invocation
finished successfully. The ledger contains 40 completions, zero pending plans,
two recovery events and 130 records. An interrupted read can execute again; this
is not exactly-once execution or power-loss recovery.

Both retained ledgers and their authenticated collector receipts were rechecked
locally during publication. Private verification keys and raw ledgers are not
published. The public summary reports operator-verified results, not independently
replayable receipt authentication or an independent security certification.

## Collector versions must remain separate

- The agent and reconstructed-deployment runs used the **existing live collector**.
  Deployment identities matched the recorded ledgers. Retained authenticated
  acknowledgments matched the final ledger sequence and head.
- The historical agent bundle's five separate KVM cases used a **disposable local
  TLS collector**. PR #55's later five-case external-collector validation is a
  different run on a different source revision.
- Preview Worker `4e442dc2-a418-4958-aa21-9b25bb72ef08` is reported in PR #55 as
  failing its first authenticated checkpoint with HTTP 409 on `d7053d3`.
  The client failed closed and guest integration against that version did not run.
  These historical successes do not validate the preview. **Do not promote it.**

Receipt authentication does not establish collector retention or disaster recovery.
No collector deployment, promotion, key rotation, or configuration change was
performed as part of this publication.

## Published scope

[summary.json](summary.json) contains reviewed aggregate outcomes, backend identity,
source attribution and limits. The manifest contains relative source paths and
SHA-256 values. Raw logs, deployment state, keys, private evidence archives and
collector URLs are excluded from this publication.

Physical-key validation remains skipped; approved credential release remains
blocked. Arbitrary-agent coverage, multi-day reliability, persistent VM sessions,
and side-effect recovery are not established. Follow the
[reproduction guide](../../GOVERNED_AGENT_RUN.md) for a new independent run.
