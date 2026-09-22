# Security claims and evidence requirements

BULL is an experimental AI execution firewall. Security depends on enforced
permissions, containment and evidence, not model family, confidence or intentions.
The candidate is not certified, universally secure, or ready for critical
infrastructure solely because source tests pass.

| Claim | Source evidence | Additional deployment evidence / limit |
|---|---|---|
| No host command without matching command authority | full-argv, authorization binding and production entrypoint tests | Every integration must use ProductionDispatcher; trusted host excluded |
| Required Linux protections must exist before execution | production boundary tests; PR #46 pre-exec gate integrated | Supported host and KVM behavior must be re-run on current candidate |
| Child capability ceiling does not exceed parent | security-domain tests | Trusted registry, root lineage and complete integration assumed |
| Unknown/model-supplied authority is not trusted | canonicalizer and domain tests | Trusted host context must actually be host-owned |
| Credentials/network require policy before brokers | broker/domain/production tests | Broker sockets must remain inaccessible to workloads |
| Protected broker operation waits for credential approval | human approval dispatcher fixture tests | Operator channel and actual device ceremony required |
| Approval matches exact request and cannot be reused | real OpenSSH verifier; binding, concurrency and restart tests | Trusted private durable DB; no malicious administrator rollback protection |
| Ordinary signed routine URL remains usable | positive dispatcher fixture | Operator responsible for selecting non-mutating remote endpoints |
| Approval does not override denial | policy-first fixture | Existing ESCALATE remains blocked, not auto-resolved |
| Missing required approval audit prevents effect | audit fault tests and consumed-state checks | Post-effect failures mean uncertain outcome, never automatic replay |
| No unknown-result automatic replay | durable state and exception tests | At-most-once authorization is not exactly-once remote processing |
| Local ledger alterations detected | audit integrity tests | Relative to trusted head/anchor; not independent nonrepudiation |
| Approval protocol requests physical presence/verification | valid/invalid SK flag signatures checked by OpenSSH | CI uses synthetic SK keys; trusted real enrollment required |
| Bounded modeled execution and one-use approval | BullRuntime, BullSessionAudit and BullApproval TLC checks | Finite design abstractions, not implementation/kernel proofs |

Publishing, destructive host changes, security configuration updates, and writable
workspace promotion are not supplied effect adapters. They remain blocked or
unsupported. There is no claim of semantic detection of every hallucination,
universal malicious-AI detection, compromised-kernel protection, or safety of
arbitrary actions within overly broad grants.

## Evidence quality rules

A test must state the initial permissions, attempted operation, expected result,
observed effect and environment. Count assertions about return values separately
from observed effects. Keep positive allowed cases alongside denied cases. Never
turn unavailable hardware into a passing fake backend test.

`tools/release_check.py` runs source tests, three finite model checks, wheel build
and site build. It preserves logs, skips/failures, source identity and tool results.
It always reports `certified: false` and separate NOT_RUN deployment gates. A
source PASS is not a production release approval. A dirty tree is identified by
both commit and tracked-content digest; it is not evidence for the bare commit.

Required promotion evidence: clean candidate CI, genuine device ceremony, current
host production verification, current real-KVM cases, guest-to-external collector
integration, review of all adapters, and independent security assessment for
higher-risk deployment. Historical benchmark results remain historical.
