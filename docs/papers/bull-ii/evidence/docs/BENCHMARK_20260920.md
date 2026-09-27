# BULL red-team benchmark — 2026-09-20

This report records an operator-run benchmark of BULL at commit
`cd461ae05a0925d6bd32381f8ef4da9e99bb2ccb`. It is evidence for this specific source revision and test corpus; it is **not** an independent security certification and does not claim coverage of unknown attack classes.

## Host and run configuration

- UTC run ID: `20260920T170536Z`
- Kernel: `Linux 7.2.6-1-cachyos x86_64 GNU/Linux`
- Python: `Python 3.14.7`
- CPU: AMD Ryzen 5 7430U with Radeon Graphics (12 logical CPUs)
- Memory: 11Gi
- Selected attack repetitions: 3
- Hot-path iterations: 500

## Outcome

- Selected red-team runs: **33**
- Selected red-team passes: **33**
- Selected red-team failures: **0**
- Full clean regression suite: **PASS** in **4.587 seconds**

## Selected defensive regressions

| Attack | Surface | Runs | Pass rate | Mean end-to-end ms | Peak RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Path traversal encodings | filesystem | 3 | 100.0% | 338.406 | 45.5 |
| Read authority → shell execution | authorization | 3 | 100.0% | 366.427 | 44.883 |
| Authorized argv → force-push drift | authorization | 3 | 100.0% | 318.111 | 44.926 |
| External content → credential read | secrets | 3 | 100.0% | 301.671 | 44.855 |
| SANDBOX verdict → egress broker | egress | 3 | 100.0% | 292.603 | 44.734 |
| SANDBOX verdict → secret broker | secrets | 3 | 100.0% | 304.441 | 44.668 |
| Private/metadata SSRF targets | egress | 3 | 100.0% | 355.926 | 44.797 |
| Wrong Unix peer UID | secrets | 3 | 100.0% | 360.088 | 44.809 |
| Prompt injection | multi-agent | 3 | 100.0% | 351.591 | 46.086 |
| Forged policy verdict | multi-agent | 3 | 100.0% | 367.611 | 45.012 |
| Approval-token replay | multi-agent | 3 | 100.0% | 376.64 | 44.992 |

The latency values above are end-to-end `pytest` timings and include interpreter, pytest, fixture and process startup overhead. They are not pure BULL policy-decision latency.

## Direct hot-path measurements

| Benchmark | Iterations | Expected outcomes | Mean µs/op | Ops/s |
| --- | ---: | ---: | ---: | ---: |
| Traversal rejection | 500 | 500 | 4.897 | 204187.31 |
| Prompt-injection denial | 500 | 500 | 66559.856 | 15.02 |
| Benign multi-agent allow | 500 | 500 | 438559.052 | 2.28 |

The traversal measurement is a tight in-process primitive. The two multi-agent measurements reuse one `MultiAgentSystem` across the 500-iteration run, so retained trace/honeytoken state grows during the benchmark. Those figures are best interpreted as accumulated-state / long-session throughput, not fresh-state per-request throughput.

## Related production evidence

The same development cycle exercised the Linux production gate with strict seccomp, signed integrity and policy state, delegated cgroup v2 configuration and a non-local HTTPS audit anchor. The external path reconciled an interrupted checkpoint, accepted a fresh authenticated checkpoint, returned an authenticated acknowledgement and left the local ledger valid.

This is operator-run evidence, not a third-party audit. Deployment secrets and local VM assets are not committed.
