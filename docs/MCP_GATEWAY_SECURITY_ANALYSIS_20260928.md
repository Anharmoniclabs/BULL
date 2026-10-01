# MCP gateway security analysis — 2026-09-28

Reviewed source: `c65fef0e3e88ec40884b2a3bdd9ac9ebe0a29fa3`, the head of
`feat/enterprise-agent-gateway-20260927` (Anharmoniclabs/BULL#86) when this was written.

## Scope and method

This is a static source review of the local MCP connector and its host authority.
It is not a live penetration test, a deployment qualification or an independent
audit. No client (Codex, Claude Code) was attached. The test suites were run
locally on the reviewed commit (see below); they use fixtures, not a live host.

Files reviewed in full:

| File | Role |
|---|---|
| `src/bulldog/mcp_gateway.py` | Unprivileged stdio MCP connector (`bull-mcp`) |
| `src/bulldog/gateway_transport.py` | Unix-socket client/server with peer-UID checks |
| `src/bulldog/gateway_wire.py` | Bounded JSON framing and parsing |
| `src/bulldog/agent_gateway.py` | Host authority: admission, dispatch, audit |
| `src/bulldog/agent_session.py` | Lease, call budget, replay and uncertainty journal |
| `src/bulldog/agent_tool_registry.py` | Signed fixed-tool catalog validation |
| `tests/test_mcp_gateway_sdk.py` | SDK handler tests |
| `docs/AGENT_GATEWAY.md`, `docs/LOCAL_MCP_ATTACHMENT_TESTS.md` | Documented boundary and procedure |

Not reviewed: `socket_hardening.py` internals, the production and local effect
routers, the sandbox, the egress broker, `gateway_cli.py` and the `tools/` runners.
Their guarantees are assumed as documented.

## Test evidence

| Source | Result |
|---|---|
| Local run, focused gateway/MCP suites (see command below) | **132 passed**, 0 skipped. This includes the 4 `test_gateway_pentest_repro.py` cases; a pass there means the F1 defect reproduced. |
| Local run, full `pytest -q` | 834 passed, 21 subtests passed, **12 failed**. All 12 are environmental: 11 need `/usr/bin/ssh-keygen` (OpenSSH not installed in the container: `test_human_approval.py`) and 1 needs cgroup v2 (`test_deployment_setup.py::test_partial_cgroup_configuration_removes_empty_scope`). None are in gateway or MCP code. |
| CI on `c65fef0`: `test (3.11)`, `test (3.13)` (BULL security regression) | Passed |
| CI on `c65fef0`: MicroVM regression, conformance, TLA+ model check, FreshClam, guest recipe | Passed |
| CI on `c65fef0`: Cloudflare `Workers Builds: bull` and `bull-audit` | **Failed**. These are external Cloudflare builds, not part of the gateway code path. Not investigated here. |
| Branch review `docs/GATEWAY_PENTEST_20260927.md` | Focused gateway suite: 128 passed. Defect reproductions: 4 passed (a pass means the defect reproduced). |

Local environment: Linux container, Python 3.11.15, MCP SDK 2.2.0, running as
root. The editable install used the `test,mcp` extras. Focused command:

```bash
python -m pytest -q tests/test_agent_gateway.py tests/test_gateway_transport.py \
  tests/test_gateway_broker_boundary.py tests/test_mcp_stdio.py \
  tests/test_mcp_gateway_sdk.py tests/test_local_gateway.py \
  tests/test_gateway_pentest_repro.py
```

Both the local run and CI use the fixture-based suites. It does not run a live Linux authority with a
real agent account, so these results do not show that the connection is safe on
a specific host.

## Threat model

The attacker controls the model and therefore everything the MCP client sends,
and can run arbitrary code as the **agent UID**. That includes skipping `bull-mcp`
and writing raw frames to the authority socket. Trusted parties: the host kernel,
root, the authority account, the operator-signed registry and the policy bundle.

## Boundary verdict

Under that model, no path was found for the agent to create authority. That
means no path to choose argv, a URL, a capability, an account or an approval,
or to skip the lease. The important checks are in the authority, not in the
connector, so a bypassed connector changes nothing:

- **Peer identity.** The server reads `SO_PEERCRED` and drops a non-enrolled UID
  before reading any bytes (`gateway_transport.py`). `handle()` checks the UID
  again. The client verifies the server UID after `connect`, which removes
  path-check TOCTOU on the client side. The socket is `0660` in a `0710`
  directory, owned by the authority, with the agent's group.
- **Request shape.** `handle()` accepts exactly `{"method":"status"}`,
  `{"method":"list"}`, or `{method,name,arguments,call_id}` with `arguments == {}`,
  a registered `name` and a `[0-9a-f]{32}` `call_id`. The request cannot carry an
  authority-bearing field.
- **Parser.** Duplicate keys, NaN/Infinity, invalid Unicode, depth > 12,
  > 2048 nodes and oversize frames are rejected. Each connection carries exactly one frame.
- **Replay and budget.** Call IDs are unique in SQLite (`synchronous=FULL`). The
  budget is incremented in the same transaction. A `running` attempt left by a
  crash becomes `uncertain` and blocks all later calls until an operator reviews it.
  A used lease cannot resume under a new process.
- **Revocation and policy drift.** Both are checked on every request and again
  just before dispatch. `REVOKED` sits inside the authority's `0700` state
  directory, so the agent cannot remove it. An effect already admitted can still
  finish; this is documented.
- **Executable pinning.** The executable path must be canonical and outside the
  project. The file and every ancestor must be owned by root or the authority
  and must not be group- or world-writable. The SHA-256 is checked again on
  every call.
- **Failure handling.** An audit append that fails before dispatch, or any
  unexpected exception, marks the attempt `uncertain`. Transport errors return
  fixed text rather than exception details.

## Findings

Severity is rated against the documented boundary, where agent authority is
the asset. None of these findings allows unauthorized execution.

### F1 — Completed results can be lost in delivery (Medium, already known, confirmed)

The branch has already recorded this in `docs/GATEWAY_PENTEST_20260927.md`, and
this review confirms it from source. `_result()` limits stdout and stderr by
**characters** (8192 each). The transport limits are in **bytes**: 192 KiB at
the authority frame and 256 KiB at the MCP writer. JSON `\uXXXX` escaping, and
the MCP result carrying both a text copy and a structured copy, push the byte
size over those limits:

- The authority has already marked the call `completed`. `encode_message` then
  raises, the server swallows the error, and the client sees a lost response.
- A frame that is smaller at the authority can still exceed the MCP writer
  limit. `write_messages` then raises inside the task group and the whole
  connector exits.

Impact: the action ran, but the client is told it failed. That invites a manual
duplicate, and the connector can be crashed by tool output the attacker
influences. The repair recommended in the branch review is sound: budget the
fully serialized frame at both layers, truncate to fit, and set `truncated`
accurately. One further requirement: `write_messages` should replace an
oversize result with a bounded error or summary, not raise.

### F2 — Tool runtime can exceed the client's response deadline (Low, needs verification)

`request()` waits 150 s for the reply. A tool's `timeout` can be up to 120 s,
and the authority also does work outside the tool's own time limit: the
trusted-state check, policy reload, malware admission, sandbox setup and audit
appends. It also serves one connection at a time, so a `list` sent during a long
call waits in the backlog. If total time passes 150 s, the client reports
failure while the authority records `completed`, the same delivery split as F1.

Recommendation: derive the client deadline from the signed maximum tool timeout
plus a measured overhead bound, or have the authority refuse registries where
`timeout + overhead >= client deadline`. Add a test that uses a slow fixture effect.

### F3 — Connector closes on any client JSON-RPC response (Low, latent)

`validate_rpc()` requires a string `method`, so a JSON-RPC **response** from the
client is treated as malformed and ends the session. The connector sends no
server-to-client requests today, because only `tools` is advertised. If a later
SDK or feature sends `ping`, `roots/list` or elicitation, a spec-compliant
client's reply would close the connection. This fails closed, so it is safe,
but it is an availability trap. Allow `{jsonrpc,id,result|error}` shapes, or add
a test that shows no server-initiated request can be sent.

### F4 — Control and escape characters in tool output reach client UIs (Informational)

Tool stdout and stderr are returned unchanged apart from truncation. They are
labelled `untrusted tool output`, but ESC or OSC sequences, or bidirectional
text controls, may be rendered by terminal clients that display tool results.
The model-level prompt-injection risk is already documented. The terminal-rendering
risk is not. Consider stripping C0/C1 controls except `\n` and `\t`, or noting
this in `AGENT_GATEWAY.md`.

### F5 — Registry strings allow bidirectional and zero-width characters (Informational)

`_text()` rejects ASCII control characters but not Unicode format characters
(for example U+202E and U+200B) in tool names, descriptions and argv. The
registry is written by the operator, so this matters only when a reviewer reads
a registry that someone else prepared. Rejecting Unicode category `Cf` would
close this Trojan-Source-style review gap at no cost.

### F6 — Fixed URLs may name internal or link-local hosts (Informational)

The network tools require HTTPS on port 443 without credentials, but accept IP
literals and internal names such as `169.254.169.254`. The URL is signed by the
operator, so this is not agent-controlled SSRF. A registry-time warning or a
denylist for private and link-local ranges would guard against operator error.
Whether the egress broker enforces this was not reviewed.

## Residual risks (documented by the project, confirmed as still open)

- **The native agent is not contained.** Codex or Claude keeps its own shell,
  browser and other MCP servers. BULL governs only calls routed through this
  connector (`whole_agent_contained: False`).
- **A UID is not a model.** Any process running as the agent UID has the same grants.
- **Local audit.** It cannot resist a host administrator who replaces both the
  log and the key.
- **Enterprise gates remain open.** These include native-bypass tests, multi-tenant
  separation, signed release packaging and independent review, as listed in
  `bull gateway coverage`.

## Suggested next steps

1. Fix F1 at both layers and turn the reproduction tests into delivery regression tests.
2. Measure the authority's per-call overhead and bound the client deadline (F2).
3. Add the small hardening changes for F3–F5 along with that fix.
4. Repeat the full suite on a host with OpenSSH and cgroup v2, then run the live
   attachment procedure in `LOCAL_MCP_ATTACHMENT_TESTS.md` as non-root accounts.

## Remediation

Fixed on `claude/great-lamport-725s0i`, on top of `c65fef0`. The same pass
red-teamed the wider build: the operator console, the transparent egress
gateway, the host egress brokers, the audit collector, the sudo host helper,
the service launcher and the lifecycle governor. It found and fixed the gaps
marked **new** below.

### MCP gateway findings

| Finding | Fix | Regression tests |
|---|---|---|
| F1 lost or oversize results | Output is budgeted by encoded bytes (`OUTPUT_FIELD_BYTES`, `RESULT_BYTES`). An oversize result keeps `call_id`, `status`, `executed` and `returncode` and drops only output (`output_omitted`). The authority server sends that compact outcome instead of closing silently. The MCP writer answers an oversize reply with a bounded JSON-RPC error for the same request id instead of crashing the connector. | `tests/test_gateway_delivery.py` covers ASCII, BMP, astral, escape-heavy and control output at 7,800, 8,192 and 100,000 repetitions |
| F2 deadline split | The client waits `CALL_DEADLINE` = the longest signed tool timeout plus a 60 s overhead allowance. A request whose client disconnected while it was queued is skipped before admission, so it never runs after being reported lost. | `test_request_abandoned_while_queued_never_runs` (live Unix socket) |
| F3 client replies | `validate_rpc` passes well-formed `{jsonrpc,id,result|error}` replies to the SDK and still rejects malformed ones. | `test_client_replies_do_not_end_the_session`, `test_malformed_replies_still_rejected` |
| F4 display controls | C0/C1 controls (except `\n`, `\t`), CR, and bidirectional controls in tool output become U+FFFD. `controls_replaced` reports this separately from `truncated`. | `test_display_controls_are_neutralized_but_lines_kept` |
| F5 hidden registry text | Registry strings reject Unicode categories Cc, Cf, Cs, Co, Cn, Zl and Zp. argv and descriptions are also capped by encoded size. | `test_registry_rejects_text_that_reads_differently`, `test_registry_bounds_encoded_sizes` |
| F6 internal URLs | Fixed URLs must name a public host. IP literals must be public (see the shared check below), and `localhost`, `.local`, `.internal`, `.home.arpa` and single-label names are refused. | `test_fixed_urls_cannot_target_local_or_private_hosts` |

### Gaps found in the wider red team

| Area | Gap (new) | Fix |
|---|---|---|
| Operator console (`control_plane.py`) | **High.** No authentication. Any local account, including the agent's, could read the snapshot and start or stop the managed MicroVM. A web page could do the same with a `text/plain` POST (no preflight), and DNS rebinding could read the snapshot. Exception text was returned to callers. | A per-run access key is required on every `/api/` call and carried in the printed URL fragment. `Host` is checked against an allowlist (including the forwarded Codespaces host). Foreign `Origin` headers are refused and POST must be `application/json`. Oversized bodies close the connection. Errors are generic. Tests: `tests/test_console_access.py` (real HTTP server). |
| Transparent egress gateway (`egress_gateway.py`) | **High.** Only the first HTTP request on a connection was inspected. Keep-alive, pipelined and body-smuggled requests reached upstream without method/path policy or Authorization stripping. Bare CR/LF/NUL in headers could smuggle a second `Host` or `Authorization`. Path rules accepted `/v1/../admin`, encoded dot segments and `/v1-admin`. | Each connection carries one Content-Length request. Chunked bodies and trailing bytes are refused. `Connection: close` is forced and hop-by-hop and `Upgrade` headers are dropped. Header framing is strict. Client copies of injected headers are removed. Path rules match on segment boundaries. Tests: `tests/test_egress_smuggling.py`; 26 of its 30 cases fail on the previous code. |
| Transparent egress gateway | **Medium.** The default resolver connected to whatever an allowlisted name resolved to, so a rebinding answer made the gateway identity a path to internal addresses. It also sent port-80 traffic to port 443. A dotted single DNS label matched a dotted allowlist name. | The resolver requires a public address and runs off the event loop. HTTP goes to port 80. DNS labels must be hostname labels. |
| Host brokers (`egress_proxy.py`, `pinned_egress.py`) | **Medium.** The deny-list admitted shared address space `100.64.0.0/10`, which includes cloud metadata services such as `100.100.100.200`. | `bulldog.public_address.is_public` requires `is_global` for the address and for any IPv4 it embeds (mapped, 6to4, Teredo, NAT64). Every egress path now uses it. Tests: `tests/test_public_address.py`. |
| Audit collector Worker | **Low.** The checkpoint MAC was compared with `!==`, which stops at the first differing character. | `crypto.subtle.verify`, which compares in constant time. The compiled Worker was run under Node: a valid MAC gave 200, forged and non-hex MACs gave 409. |

Reviewed with no change needed: the sudo host helper (`tools/host_setup.py`),
`tools/serve_agent_gateway.py`, `gateway_cli.py` revocation, the lifecycle
governor's grant and approval binding, the egress installer and systemd unit,
and secret comparisons elsewhere (all use `hmac.compare_digest`).

### Validation after remediation

Linux container, Python 3.11.15, MCP SDK 2.2.0, OpenSSH installed, running as root:

| Check | Result |
|---|---|
| Full `pytest -q` | **978 passed**, 1 skipped, 21 subtests passed, 1 failed. The failure needs cgroup v2 (`test_partial_cgroup_configuration_removes_empty_scope`), which the container lacks. The skip is the live huge-result transport test, because the client correctly refuses a root authority; a unit test covers that path. |
| `python -m compileall -q src/bulldog` | Passed |
| `tools/adversarial_check.py` | 49 probes, 49 held |
| `tools/check_package.py` | Passed |
| `node --check` console script | Passed |

### Still open

- Operational issue, not changed here: with the guest nftables rules, a local
  stub resolver's upstream queries are redirected back into the gateway.
  Setting `--dns-upstream` to the guest's real resolver avoids this loop.
- The residual risks listed above are unchanged. The native agent is still not
  contained, and no live Codex or Claude Code attachment has been run.
