# BULL in five minutes

**BULL separates a model's proposed action from the authority to execute it.**
It is experimental Linux execution-governance infrastructure, not a claim that
an AI model can be made universally safe.

## 1. Problem — 45 seconds

Agents encounter untrusted documents, tool output and other agents. Useful input
must not automatically become permission to run a command or retrieve a credential.

## 2. Boundary — 60 seconds

Show: proposal → production dispatcher → capability and exact-command checks →
constrained execution → authenticated receipt. Identify the trusted host, kernel,
operator and authority storage. Mention the host sandbox and one-shot KVM paths
as separate integrations.

## 3. Evidence — 90 seconds

Open [the validation record](VALIDATION_20260923.md), pinned to `428db9c`:
437 tests + 6 subtests; seven GitHub jobs; five real KVM cases; authenticated
external host/guest receipts; allowed and denied fixed-tool requests.
Explain the controlled worker, collector and storage-failure tests.

Then show [PR 57](https://github.com/Anharmoniclabs/BULL/pull/57), merged into
`main`: approved branding, diagnostic firmware, hardware assertion verification
through the existing ApprovalGate, and the dependency update. Its integration
suite passed 489 tests + 21 subtests. Software-generated signatures test request
binding and durable consumption; they are not physical signing evidence.
Use the release candidate's `VALIDATION.json` for its exact source and guest
versions rather than combining these revision-specific results.

The older Qwen demonstration ran 40 actions in 11m 47s with two recoveries.
It used two fixed read-only tools on the host, not the MicroVM. Do not combine
its source revision or test counts with the newer candidate.

## 4. Demonstration — 60 seconds

Use the recorded allowed, denied and timeout results from the same candidate.
For a live rehearsal, follow [MicroVM integration](../microvm/README.md) with
fresh disposable local infrastructure. Keep private keys and raw logs off-screen.
The architecture film illustrates the design; it is not an execution recording.

## 5. Limits and review request — 45 seconds

The connected hardware is only a KB2040, with no secure element. Physical approval
remains blocked. Persistent VM state recovery, host power loss,
collector disaster recovery and broad third-party adapters remain unverified.
There is no independent security certification or endorsement by a meeting organizer.
Ask reviewers about mediation coverage, operator trust and recovery semantics.

The project source is publicly licensed. The historical binary guest release now
includes matching source and license materials; see [distribution status](DISTRIBUTION.md).
Present the reviewed source and measured evidence, not an unqualified production release.

[Longer technical Q&A](OCTOBER_REVIEW.md) · [Contributing](../CONTRIBUTING.md)
