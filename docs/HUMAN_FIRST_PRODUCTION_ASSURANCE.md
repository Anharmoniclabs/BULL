# Human-first production assurance

BULL's purpose is to keep authority with the operator. A model, retrieved page,
tool response or workload may propose an action. It must not create its own
permission, enroll an approval credential or declare its own deployment safe.
This document separates the implemented controls from the evidence still needed.

## What the production router covers

`ProductionEffectRouter` accepts three operation names: `process.execute`,
`network.request` and `secret.read`. It checks parameter shapes and calls
`ProductionDispatcher`. Unsupported operations are denied at that entry point.
This does not establish that every existing adapter or arbitrary callable uses it.

Process execution uses signed policy and dispatch authority. Consequential broker
effects use the approval gate and `DurableEffectJournal`. There is an explicit
exception for policy-authorized routine GET/HEAD requests in
`ProductionDispatcher._perform_broker_effect`; these do not consume a fresh
approval or journal entry. Read that branch before claiming all requests require
a human signature.

The journal consumes a key before dispatch. An uncertain external result requires
trusted reconciliation and is not automatically retried. Exactly-once delivery
also requires a contract with the external service; local bookkeeping alone
cannot establish it.

## Combined guest candidate: observed result

The operator supplied a Codespaces transcript for clean source
`e6df4de481900262bb322e5c26d65967df8bf9bb`. The direct-init lab reported 12 passing
checks. Its systemd candidate reported the same checks plus active service units,
for 13 passing checks. The transcript is operator-reported evidence; the private
reports and images have not been independently inspected for this documentation.

| Area | Named checks in the final candidate |
|---|---|
| Separate identities | `agent_workload_uid`, `gateway_uid` |
| Allowed traffic | `direct_gateway_http`, `allowed_http` |
| Denied traffic | `denied_http`, `denied_dns` |
| Alternative routes | `ipv4_alt_closed`, `ipv6_alt_closed`, `ipv6_web_closed` |
| Firewall observation | `filter_drop_counters` |
| Stop and restart | `gateway_down_closed`, `restart_still_denies` |
| Service startup | `service_units_active` |

The fixture is a disposable Debian KVM guest with `bullagent`, `bullgw`, nftables
and systemd. QEMU uses restricted user networking. The workload makes controlled
network probes; it does not demonstrate the complete production dispatcher path.
Passing these checks is not a measured probability of resisting arbitrary attacks.

From a clean KVM-enabled Codespace operator shell, in the repository root:

```sh
python3 tools/run_codespace_combined_candidate_kvm.py --install-deps
```

The runner creates a direct-init lab and clones it into a systemd candidate. Keep
the printed evidence directories private. The separately pinned offline image
continues to use `-net none`; this test does not turn it into a networked release.
A new source revision needs its own run to claim current deployment evidence.

## Next end-to-end check

Build and pin a separately versioned networked image containing the agent
workload, router, actual production dispatcher state, gateway, network rules and
service units. Exercise allowed and denied commands, network and secret effects,
approval failures and audit outages through the actual workload path. Bind its
reports to the source revision and image hashes. This remains separate from the
13-check candidate result above.

## Other implemented controls to inspect

- Exact command and request binding in the production dispatch path.
- Broker-controlled secret release for a named use.
- Separate workload and gateway users in the guest candidate.
- Read-only raw namespace workspaces by default; writable binds use
  `nosuid,nodev`, and root cannot request a writable host workspace.

These are implementation claims. Consult [the code map](CODE_READING_GUIDE.md)
and [security model](PRODUCTION_SECURITY.md) for their boundaries. Do not infer
universal mediation of browser actions, messages, stored memory or other adapters.

## Long-duration testing and outside review

`tools/run_assurance_campaign.py` repeats a trusted qualification command and
writes a durable hash-only record per iteration. It binds the final report to an
unchanged source revision. Its zero-failure statistical bound assumes independent,
representative trials of the named fixture. It is not a universal escape rate,
and a runner's existence is not evidence that a multi-day campaign has completed.

An outside reviewer should receive the source revision, image hashes, threat
model, adapter coverage, failures, sanitized reports and exact commands. Reviewers
must choose additional attacks; reproducing the author's suite is not equivalent
to an independent adversarial review.

## Trust limits

A malicious administrator, compromised kernel or hypervisor, hardware flaw or
unknown VM escape can defeat controls below that trust boundary. Prompt injection
controls restrict the authority of untrusted text at covered effect boundaries;
they cannot prove safety against every future model behavior. End-to-end signed
hardware approval and formal equivalence between the design models and Python
still require their own evidence.
