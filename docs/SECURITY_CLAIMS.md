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


## Correctness evidence and issue #51

The acceptance question is whether an unauthorized effect occurs, not whether an
API raises an exception. `ExecutionResult(executed=False, evaluation=DENY)` is a
normal denial. HUMAN provenance never substitutes for a capability grant in
`DeterministicPolicy`. The current production path requires exact host-authorized
argv and a dispatcher-minted permit. Development dispatch permits an omitted
`authorized_command`; it is intentionally not the production boundary.

There is no separate global executable-path allowlist in the policy bundle.
The host must restrict which exact command vectors it authorizes. A valid broad
process grant plus host authorization of an interpreter is broad authority;
BULL does not understand every consequence of arbitrary authorized code. A
nonexistent executable being considered by development dispatch is not evidence
of successful execution, nor evidence of an implemented executable allowlist.

Issue #51's historical harness classified normal returns as failures without
checking `executed` or sandbox effects. New tests in
`tests/test_full_argv_and_production_wiring.py` check empty grants on both paths,
missing production argv, argument drift and executable substitution before a
recording sandbox/runtime receives the action. Host construction is stubbed in
those unit fixtures: these tests establish authorization behavior, not isolation.
The same file retains an exact-vector positive control. Real isolation evidence
comes separately from strict-host and KVM tests.

| Requirement | Current implementation | Test/evidence |
|---|---|---|
| Deny ungranted execution before effects | policy.py, profiles.py, runtime.py | test_full_argv_and_production_wiring.py; test_policy.py |
| Production entrypoints require trusted construction and permit | profiles.py, dispatcher.py | redteam_local_host/test_production_entrypoints.py |
| Child/sibling authority stays constrained | security_domain.py | test_security_domains.py |
| Policy, integrity and prerequisites fail closed | policy_bundle.py, integrity.py, production_gate.py | test_production_boundary.py; test_policy_hardening_v2.py |
| Approval binds exact consequential broker request | profiles.py, approval.py, approval_crypto.py | test_human_approval.py (synthetic credentials) |
| Ledger mutation/truncation fails against trusted state | audit.py, audit_transport.py | test_audit_fail_closed.py; test_audit_integrity.py; test_anchor_service.py |
| CPU/memory/pids enforcement and cleanup | cgroup_scope.py | tools/cgroup_check.py real bounded probes; test_cgroup_check.py optimization regressions |
| Guest execution requires protection and completes/cleans up | guest_engine.py, microvm.py, microvm/integration.py | allowed/denied/timeout/cancel/missing-protection KVM cases |
| Receipt binds session, sequence and head | audit_transport.py, microvm/evidence.py | deployment_check.py external host and guest checks |

Finite tests establish those observed cases, not absence of every bypass. Audit
MACs establish authentication relative to shared secret custody, not independent
nonrepudiation. Coordinated rollback of every trusted copy, compromised keys,
malicious administrators and untested retention guarantees remain outside the
claim. An uncertain post-effect result must not be presented as an undone effect.

## Repository governance: issue #9

The GitHub API inspection on September 22 (local time) found active ruleset
`23703169`, targeting main, with no bypass actors, required PRs, resolved review
threads, signed commits, blocked deletion/force pushes, and up-to-date required
checks: Python 3.11/3.13, formal models and MicroVM host regression 3.11/3.13.
The classic branch-protection endpoint returned 404; the ruleset API is the
applicable evidence. Zero approving reviews are required: do not claim an
independent human review is enforced. No repository settings were changed.
