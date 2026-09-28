# Composing an Authority Layer with a Sandbox Runtime: BULL on NVIDIA OpenShell

**An empirical qualification against a live OpenShell v0.1.2 gateway**

Date: 2026-09-28 · Branch: `experiment/bull-openshell-20260928` ·
Evidence: [`docs/evidence/openshell-20260928/`](../evidence/openshell-20260928/)

---

## Abstract

NVIDIA OpenShell runs agents in sandboxes. Each sandbox enforces a declarative
network and filesystem policy and emits OCSF telemetry. It also exposes two
extension points: a gateway interceptor on control-plane RPCs and a supervisor
middleware on each proxied HTTP request. BULL is an authority layer. It decides
from signed grants, content provenance and single-use human approvals whether
an agent's action is permitted, and it records every decision in a hash-chained
ledger. We built BULL as an OpenShell interceptor and middleware and tested one
invariant against a real gateway built from source:

> `EFFECT = BULL_authorized ∧ OpenShell_policy_allowed`, and a missing or
> failing BULL means no effect.

We used a 10-case proof suite plus two extra cases (C3b, C5b). Each case ran
in two phases, OpenShell alone (A) and OpenShell with BULL registered
fail-closed (B). We judged effects at the destination: a request counts as
"blocked" only if the upstream server never received it. **All 26 checks
passed in the final run.** Composition cost a median **+8.1 ms** per GET and
**+11.0 ms** per POST (n = 200 each), with no significant change to sandbox
creation time.

The experiment also produced findings that matter to anyone deploying either
system:

1. OpenShell's L7 rules default to `enforcement: audit`, which logs
   violations and then **allows** them. We measured this directly in C3b-A.
2. OpenShell v0.1.2 hands middleware the scheme `https` for plaintext HTTP
   relays and never populates `originating_process`.
3. BULL's ledger append re-verifies the whole chain, which makes latency grow
   with ledger size.

We fixed six integration defects in BULL during the run; all are listed in §6.

---

## 1. Motivation

A sandbox answers *where* code may reach. An authority layer answers *whether
this particular action, now, given where its inputs came from, is authorized
and by whom*. Each is weak alone:

- **OpenShell without an authority layer.** It has no notion of content
  provenance. A sandbox that reads attacker-controlled text can POST to any
  endpoint its policy allows (C4-A and C7-A below). Its policy can be widened
  by anyone who can call `UpdateConfig` (C5-A).
- **BULL without a sandbox.** BULL's decisions bind only on traffic that
  passes through it. A native tool that skips BULL's proxy is outside BULL's
  view.

The question is whether both can be composed so each covers the other's gap,
without the composition opening a new bypass. The failure mode we most wanted
to exclude is fail-open: BULL down, and effects happening anyway.

## 2. System under test

### 2.1 OpenShell extension points used

| Extension | Where it runs | What BULL does there |
|---|---|---|
| Supervisor middleware (`SupervisorMiddleware/EvaluateHttpRequest`, phase `PRE_CREDENTIALS`) | Called by each sandbox's supervisor for each proxied HTTP request, after OpenShell's own L7 policy and before credential injection | Returns `ALLOW` or `DENY`. It can only narrow what OpenShell's policy already allowed |
| Gateway interceptor (`GatewayInterceptor/Evaluate`) | Called by the gateway on control-plane RPCs | `modify_operation`: attaches BULL middleware (`onError: fail_closed`) to every host in a new or replacement policy. `validate`: refuses unmediated sandboxes, audit-mode L7 rules, hosts outside the signed ceiling, and any unapproved widening |

Governed RPCs:

- `CreateSandbox` and `UpdateConfig`: modify_operation and validate.
- `AttachSandboxProvider`, `ApproveDraftChunk`, `ApproveAllDraftChunks` and
  `EditDraftChunk`: validate only.

Both extensions are registered with `failure_policy = "fail_closed"`.

### 2.2 BULL components added (`src/bulldog/openshell/`)

| Module | Role |
|---|---|
| `grants.py` | Per-sandbox grants (`bull-openshell-grants-v1`) inside the HMAC-signed BULL policy bundle: host ceiling, capabilities, trusted `host:port` sources |
| `authority.py` | Decisions. HTTP method maps to capability; provenance becomes INTERNET once a sandbox has read an untrusted source; ESCALATE yields a pending approval bound to the exact method, URL and body hash, consumed once. Control-plane checks cover widening, the ceiling, audit mode and credential attach. State persists across restarts |
| `services.py` | gRPC servicers for both extension protocols (PeerMetadata 1.0, contract capabilities) |
| `server.py` | Process entry point, plus a private operator socket (`pending`, `approve`) |
| `ocsf.py` | Parses OpenShell OCSF shorthand as served by `openshell logs`, and joins it with the BULL ledger and observed effects |
| `backend.py` | Health and extension-presence probe (`require_strict`) |

## 3. Method

### 3.1 Environment

| Item | Value |
|---|---|
| OpenShell | v0.1.2 (commit `6648bd0`), built from source with Rust 1.95.0. Gateway, CLI and supervisor are glibc builds; the sandbox runtime is a static musl build |
| Compute driver | Docker 29.3.1 (`image_pull_policy = "never"`) |
| Host | Linux 6.18.44, 4 vCPU, 15 GiB, cloud container |
| Sandbox base image | `ubuntu:24.04` plus curl and python3, run as uid 1500 |
| BULL | Python 3.11, grpcio 1.84, protobuf 7.36 |
| Transport | Middleware over plaintext gRPC on the Docker bridge (`allow_insecure_transport = true`); interceptor on a Unix socket |

**Deviations from a stock OpenShell install.** The sandbox's network policy
blocks `ghcr.io`, `nvcr.io` and GitHub release downloads, so we could not use
the official installer or published images. We built all images locally from
the upstream Dockerfiles, with two changes:

- **Supervisor base image.** The supervisor image uses
  `gcr.io/distroless/cc-debian13` instead of the pinned
  `distroless/base-nossl-debian13`, because a locally built supervisor needs
  `libgcc_s`.
- **Host alias.** The host maps `host.openshell.internal` to the Docker bridge
  (172.17.0.1) in `/etc/hosts`, so the gateway, which runs on the host, can
  reach the middleware at the same address the supervisors use.

Policies declare `allowed_ips: ["172.17.0.1/32"]`, because OpenShell's SSRF
guard otherwise blocks the private bridge address.

### 3.2 Topology

Three host-side HTTP services act as destinations and record every request
that reaches them:

- **docs:** trusted by BULL.
- **news:** untrusted; it returns a prompt-injection string.
- **api:** the effect target.

OpenShell's policy allows:

- `GET /**` on docs and news
- `POST /v1/**` on api

All three endpoints set `enforcement: enforce` and limit the binary to
`/usr/bin/curl`.

BULL grants:

| Sandbox | Capabilities | Trusted source |
|---|---|---|
| `coder` | outbound + post | docs |
| `reader` | outbound only | docs |
| `bench` | outbound + post | docs |

The host ceiling is `host.openshell.internal`.

### 3.3 Phases and judging

- **Phase A:** OpenShell only.
- **Phase B:** the same policies and requests, with both BULL extensions
  registered.

A case passes on effect evidence, meaning upstream receipts, never on client
output alone. Phase A rows for BULL-specific cases record what OpenShell
alone does. A phase A "pass" means the observation was made as expected, not
that the property holds.

### 3.4 Latency

Inside one `bench` sandbox, a shell loop runs `curl -w %{time_total}` 200
times for a trusted GET and 200 times for an allowed POST. This keeps
`sandbox exec` overhead out of the samples. Sandbox creation time is the
`openshell sandbox create --detach` wall time over 6 creations; it measures
admission, including interceptor round-trips, not boot to Ready.

The harness is `tools/openshell_experiment.py`. It is fully automated and
builds, runs, collects and tabulates.

## 4. Results

### 4.1 Proof suite (final run)

| Case | Property | A: OpenShell only | B: OpenShell + BULL |
|---|---|---|---|
| C1 | BULL ALLOW ∧ OpenShell ALLOW → effect | 200, reached | **200, reached** ✅ |
| C2 | BULL DENY ∧ OpenShell ALLOW → no effect (`reader` has no post grant) | 200, **reached** (no authority layer) | **403, not reached** ✅ (`bull_denied`) |
| C3 | BULL ALLOW ∧ OpenShell DENY (`POST /admin/delete`, outside L7 rules) → no effect | 403, not reached | **403, not reached** ✅ |
| C3b | Same L7 rules left at OpenShell's default enforcement | sandbox created; `POST /admin/delete` **reached** | **creation refused** ✅ (`bull_l7_audit_mode`) |
| C4 | ESCALATE: no effect before approval; exactly one after; none on reuse | 200, reached (no approval concept) | **403 → approve → 200 → 403**; upstream count exactly 1 ✅ |
| C5 | Unauthorized policy widening (new port on an allowed host) | applied (policy v3 loaded) | **refused**: `approval … required to widen policy with ['host.openshell.internal:9']` ✅ |
| C5b | Sandbox policy naming a host outside the signed ceiling | (n/a) | **refused** (`bull_outside_ceiling`) ✅ |
| C6 | Provider credential never readable by the agent | canary not in sandbox env | attach **refused** (no `credential.read` grant); canary not in env ✅ |
| C7 | Internet-derived content, then POST, hits provenance control | POST after reading `news` **reached** | **403, not reached** (`bull_approval_required`, provenance `internet`) ✅ |
| C8 | Native bypass: `curl --noproxy`, a Python HTTP client, a raw socket to 1.1.1.1:443, UDP DNS to 8.8.8.8 | `--noproxy` POST reached, but *mediated* (OCSF L7 event present); Python HTTP and raw socket EACCES; UDP blocked | `--noproxy` POST **intercepted and escalated by BULL** (not reached; OCSF shows both `l7` and `middleware`); others blocked as in A ✅ |
| C9 | BULL process killed: egress and sandbox creation fail closed | (n/a) | POST **403** (`middleware_failed: external_service_error`), not reached; `CreateSandbox` **refused**; after restart, trusted GET 200 with taint and approvals preserved ✅ |
| C10 | OpenShell events, BULL decisions and effects form one audit trail | 8 L7 events, no authority record | **9/9** BULL decisions matched to OpenShell middleware events and consistent; **0** effects without a BULL allow; the 1 orphan OpenShell event is the C9 fail-closed denial; ledger hash chain verifies ✅ |

Totals: phase A, 12/12 observations as expected. Phase B, 14/14 properties
held. Both include the two setup rows.

### 4.2 Audit correlation detail (C10, phase B)

| Sandbox | Request | BULL | OpenShell L7 | OpenShell middleware | Effect |
|---|---|---|---|---|---|
| coder | GET docs/guide | ALLOW | ALLOWED | ALLOWED | yes |
| coder | POST api/v1/records | ALLOW | ALLOWED | ALLOWED | yes |
| reader | POST api/v1/records | DENY | ALLOWED | DENIED (`bull_denied`) | no |
| coder | GET news/article (taints) | ALLOW | ALLOWED | ALLOWED | yes |
| coder | POST api/v1/records | ESCALATE → pending | ALLOWED | DENIED (`bull_approval_required`) | no |
| coder | same POST after approval | ESCALATE → approved (consumed) | ALLOWED | ALLOWED | yes (exactly once) |
| coder | same POST again | ESCALATE → pending | ALLOWED | DENIED | no |
| coder | POST api/v1/x (`--noproxy`) | ESCALATE | ALLOWED | DENIED | no |
| coder | GET docs/after-restart | ALLOW | ALLOWED | ALLOWED | yes |

The L7 column is ALLOWED on every row. That is the point of the composition:
OpenShell's policy alone would have let every one of these requests through.

OpenShell carries BULL's reason code into its own denial telemetry, for
example `middleware_denied:bull-governance:bull_approval_required`. A SIEM
that ingests only OCSF can therefore still see why BULL refused.

### 4.3 Latency

Per request, measured inside the sandbox; n = 200 per cell; values in ms.

| Metric | Phase | Mean | Median | p95 | Min | Max | σ |
|---|---|---|---|---|---|---|---|
| GET (trusted) | A | 10.23 | 8.99 | 16.92 | 6.36 | 31.20 | 3.49 |
| GET (trusted) | B | 17.88 | 17.07 | 26.03 | 11.43 | 43.46 | 4.34 |
| POST (allowed) | A | 11.46 | 9.85 | 21.17 | 6.65 | 33.86 | 4.60 |
| POST (allowed) | B | 22.65 | 20.83 | 34.17 | 14.42 | 65.33 | 6.60 |

Sandbox creation, n = 6, in seconds:

| Phase | Mean | Median | p95 | Min | Max |
|---|---|---|---|---|---|
| A | 0.914 | 0.925 | 0.939 | 0.811 | 1.026 |
| B | 0.986 | 0.995 | 1.010 | 0.908 | 1.058 |

Derived observations:

- **Per-request overhead.** Median +8.1 ms per GET and +11.0 ms per POST.
  From OCSF timestamps, OpenShell's L7 event precedes the middleware verdict
  by a median of 5.0 ms (range 1–7 ms, n = 10). That is the BULL round-trip
  as the supervisor sees it: plaintext gRPC over the bridge, the Python
  decision, and a synchronous ledger append.
- **Admission overhead.** About +70 ms mean per sandbox creation (two
  interceptor round-trips on a Unix socket). With n = 6 and σ ≈ 50–70 ms,
  this is at the edge of the noise.
- **Drift with ledger size.** Phase B latency rises across the run: median
  of the first 50 versus the last 50 samples goes 14.9 → 17.7 ms (GET) and
  19.5 → 25.1 ms (POST). Phase A stays flat (9.1 → 9.7 and 10.3 → 9.2).
  BULL's `AuditLedger` re-verifies the entire hash chain before every append,
  so append cost is O(n) in ledger length. This is the most likely cause; we
  did not isolate it. It also explains why POST overhead exceeds GET
  overhead: the POST loop ran second, against a longer ledger. A persistent
  tail-hash check would make appends O(1).

## 5. Findings about the components

**F1. OpenShell L7 rules default to audit (C3b-A).** An endpoint with L7
rules and no `enforcement` field logs a violation and forwards the request.
We observed `POST /admin/delete` reaching the upstream despite a rule
allowing only `POST /v1/**`. The OCSF event reads `ALLOWED … engine:l7`.
OpenShell documents this default. Operators who write rules and never set
`enforcement: enforce` get no enforcement.

BULL now refuses such policies at `CreateSandbox`, `UpdateConfig` and rule
merges (`bull_l7_audit_mode`). The check accepts both the YAML form
(`enforce`) and the protobuf-JSON enum form
(`NETWORK_ENFORCEMENT_MODE_ENFORCE`); `UNSPECIFIED` is treated as audit.

**F2. Transparent interception holds (C8).** OpenShell's policy DNS resolved
`host.openshell.internal` to a trap address (198.18.0.2). Traffic sent with
`--noproxy` was still captured, L7-evaluated and, in phase B, sent through
BULL. Binary identity refused the Python client (EACCES) even though curl was
allowed to the same endpoint. Neither a raw socket to a public IP nor UDP DNS
got out.

**F3. Middleware metadata gaps in v0.1.2.**

- `HttpRequestTarget.scheme` is set to `https` on relay paths that carry
  plaintext HTTP. OpenShell's own OCSF events for the same requests say
  `http`.
- `RequestContext.originating_process` is hard-coded to `None` for operator
  middleware, so BULL cannot bind decisions to the executable. Every
  `binary` field in the BULL ledger is empty.

BULL therefore must not trust `scheme`; the correlator compares only
host, port and path.

**F4. Extension contract is strict and fails closed.** Two mistakes each
blocked the path completely rather than opening it:

- Replies whose `reason_code` does not match `[a-z][a-z0-9_]*` are treated as
  middleware failure (`response_reason_code_invalid`), and the request is
  denied.
- An extension that omits the `openshell.<family>.contract` capability is
  refused at gateway start.

**F5. OCSF JSONL export depends on a writable `/var/log` in the supervisor
container.** It is not writable in the Docker driver's image, so enabling
`ocsf_json_enabled` produced no file. The same events are available as
shorthand through the gateway (`openshell logs`), which is what C10 uses.

**F6. `openshell sandbox exec` reads a non-TTY stdin to EOF before
dispatching.** Automation that inherits an open stdin hangs indefinitely.
Pass `/dev/null`.

## 6. Defects found and fixed in BULL during the experiment

All six were invisible to BULL's unit tests and surfaced only against the
live gateway. Each fix has a regression test (`tests/test_openshell_authority.py`,
28 tests).

| # | Defect | Symptom on the live system | Fix |
|---|---|---|---|
| 1 | Missing contract capabilities in `PeerMetadata` | Gateway refused to start | Declare `openshell.<family>.contract` as supported and required |
| 2 | Dotted reason codes (`bull.denied`) | Every request denied as `middleware_failed: response_reason_code_invalid`, fail-closed but useless | Codes renamed to `bull_*`; grammar test added |
| 3 | Protobuf-JSON ports are doubles (`40605.0`) | Endpoint keys `host:40605.0` would never match later `host:40605` checks, a latent false-widening or bypass | Normalize to int; also cover every entry in `ports` |
| 4 | No audit-mode check | OpenShell-deny cases silently became allow (F1) | `bull_l7_audit_mode` refusal |
| 5 | Enum form of `enforcement` not recognized | After fix 4, every sandbox was refused | Accept the `NETWORK_ENFORCEMENT_MODE_ENFORCE` enum name |
| 6 | Correlator let a denied decision claim a nearby allowed request's receipt | C10 reported a false "effect without allow" | Effects assigned only to allowed decisions at or after decision time; leftovers are the violation signal |

## 7. Threats to validity and limitations

- **Unauthenticated extension transport.** The middleware ran over plaintext
  gRPC with `allow_insecure_transport`, and OpenShell warns that the service
  "cannot distinguish OpenShell from any other network client". Any process
  on the bridge could have queried BULL's verdicts, though not changed an
  enforcement outcome. Production needs https with gateway-JWT validation.
  We did not test that configuration.
- **Single host, Docker driver only.** No Kubernetes, VM or hardware-isolated
  drivers. Numbers come from a 4-vCPU shared cloud container and include its
  noise.
- **Exec is not mediated by BULL.** BULL sees HTTP egress and control-plane
  RPCs, not process execution inside the sandbox. OpenShell's Landlock,
  seccomp and binary identity contain exec (F2), but BULL does not authorize
  it. The "exec" half of the architecture's C7 is therefore OpenShell's
  guarantee, not BULL's.
- **WebSocket traffic is not mediated.** BULL does not bind that operation.
- **C6 phase A is weak evidence.** The provider attachment was still
  `waiting_for_supervisor` when the environment was checked, so absence of
  the canary in phase A does not show that OpenShell's placeholder mechanism
  works. Phase B's result rests on BULL refusing the attach, not on
  placeholders.
- **Correlation is heuristic.** OCSF shorthand carries no request id, so
  events are joined by sandbox, method, target and a 3 s window, and effects
  by method, target and time. The join was exact in this run, where requests
  were serialized. Under concurrency, identical requests could be swapped.
  That would not change the counts the property is judged on, but it would
  change row attribution. OCSF JSONL with request ids (F5) would remove the
  ambiguity.
- **Few runs.** Three complete runs were made. The first surfaced defect 5
  (phase B could not start). In the last two, every case outcome was
  identical except C10, whose earlier failure was defect 6 in the
  correlator, not the system. Latency figures come from the final run only.
- **Approvals.** Approval used BULL's local operator socket. Human latency is
  not part of any measurement.

## 8. Conclusion

On a live OpenShell v0.1.2 gateway, BULL composed as a narrowing-only layer:

- Every effect needed both systems' consent.
- BULL's absence failed closed at both the data plane and the control plane.
- Provenance-based escalation stopped exfiltration after untrusted input,
  which OpenShell's static policy allowed in the baseline.
- Unauthorized widening and credential attachment were refused.
- The two systems' records joined into one consistent trail.

The main cost is about 8–11 ms per request in this build, much of it
attributable to BULL's synchronous O(n) ledger verification. The main risk
we found is not in the composition but in a default: OpenShell's audit-mode
L7 rules. BULL now refuses them.

## Reproduction

```bash
# OpenShell v0.1.2 source at $OS, built:
#   cargo build --release -p openshell-cli -p openshell-gateway -p openshell-supervisor
#   cargo build --release --target x86_64-unknown-linux-musl -p openshell-sandbox
echo "172.17.0.1 host.openshell.internal" >> /etc/hosts
pip install -e '.[openshell]'
python tools/openshell_experiment.py --os-src "$OS" \
    --output docs/evidence/openshell-20260928 --latency-n 200
```

Artifacts in the evidence directory:

- `results.json`: all cases, metadata, latency summaries.
- `cases.csv`, `latency.csv`, `latency-raw.json`.
- `correlation.json`: C10 join, orphan events, unexplained effects.
- `bull-audit.jsonl`: BULL hash-chained ledger, phase B.
- `ocsf-*-{A,B}.txt`: OpenShell OCSF events per sandbox, as served by the
  gateway.
- `upstream-receipts-{A,B}.json`: what the destinations received.
- `gateway-{A,B}.{toml,log}`, `bull.log`, `policy.yaml`.
