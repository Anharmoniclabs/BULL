# Human-first production assurance

## Authority rule

An agent, model, retrieved document, tool response or workload process is an
untrusted proposer. It cannot create permission, register a production adapter,
enroll an approval credential, change policy, choose an evidence directory or
declare its own result successful. Those actions remain host/operator owned.

The only currently routable agent-facing production effects are declared by
`ProductionEffectRouter`: exact process execution, a network request and secret
use. The latter two retain the existing signed human-approval gate and now use
`DurableEffectJournal`. Unsupported message, publish, persistence, replication,
access-control and security-control effects fail closed until a typed production
adapter is implemented. Development callables do not become production adapters.

## Contamination controls

* External text and derived memory retain untrusted provenance.
* Exact executable, arguments, target and parameters are bound before use.
* Network access is mediated by explicit policy and guest nftables.
* Secrets are released by a peer-authenticated broker for one named use.
* Consequential operations require a short-lived credential signature.
* A durable effect key is consumed before the external call. Uncertain calls are
  reconciled by a trusted observer and are never automatically repeated.
* Agent workloads run under a separate `bullagent` UID in the networked KVM
  candidate. The gateway remains a distinct unprivileged `bullgw` UID.
* Raw namespace workspaces are read-only by default. Writable binds are
  `nosuid,nodev`, and a root service cannot request a writable host workspace.

## Claims that remain bounded

A malicious host administrator, compromised kernel/hypervisor, hardware flaw or
unknown VM escape can defeat software controls below that trust layer. BULL must
report those assumptions instead of converting them into a PASS. Prompt
injection resistance means injected text lacks authority at covered effect
boundaries; it cannot mean that every future string or model behavior was tested.

## Required production candidate

Preserve the pinned `-net none` image. Build a separately versioned candidate
containing the agent workload UID, `ProductionEffectRouter`, actual
`ProductionDispatcher` deployment state, `bullgw`, nftables and the actual
systemd unit. Run allowed and denied commands plus HTTP, DNS, raw-IP, alternate
IPv4/IPv6, gateway-stop/restart and audit-outage cases from the `bullagent`
process. Bind reports to the clean source commit and image hashes. A candidate
failure cannot be relabeled as an environmental skip.

## Long-duration and statistical evidence

`tools/run_assurance_campaign.py` repeatedly executes a trusted qualification
command, fsyncs one hash-only record per iteration and binds the final report to
an unchanged source revision. With zero failures it reports a one-sided 95%
binomial upper bound. That number is meaningful only for representative,
independent trials of the named fixture. It is never a universal escape rate.

## Independent review package

Give reviewers source commit and image hashes, this threat model, production
effect coverage, setup scripts, failures, sanitized reports and exact rerun
commands. Keep disposable credentials and private guest images out of the public
bundle. Reviewers must select additional attacks; executing only the author's
suite is reproduction, not an independent adversarial review.

## One-command combined KVM candidate

From a clean KVM-enabled Codespace operator shell:

```bash
python3 tools/run_codespace_combined_candidate_kvm.py --install-deps
```

This produces a fresh direct-init gateway lab and a cloned final systemd
candidate. Its PASS covers distinct `bullagent` and `bullgw` UIDs, nftables,
gateway behavior and actual service units in that disposable Debian image. It
still reports the dispatcher workload route and pinned image release as separate
gates.
