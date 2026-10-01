# Connected-tool gateway implementation checks

Validated code commit: `d5d02a26bd71e71f04961a09e065aeab29f88662`.
Tree: `218576891a5534146cb7eb47908f95dcc3166737`.
Date: 2026-09-27. Python 3.12; MCP SDK 2.2.0.

| Check | Observed result | Scope |
|---|---|---|
| Full source regression | 722 passed, 21 subtests passed, 4 failed, 2 skipped | Full suite is **not green** in this environment |
| Gateway/router subset | 69 passed, 2 skipped | Production-method authorization, policy, SDK handlers, lease and parser tests |
| Real MCP stdio exchange | PASS | SDK handshake, tool listing and serialized response; authority is an explicit transport fixture |
| Real Unix broker/client and wrong-peer checks | SKIPPED | Host forbids creating Unix sockets; no IPC qualification claimed |
| Production Linux sandbox integration | BLOCKED by host | User namespace mapping is denied; no new live isolation qualification |
| Committed sdist → wheel → fresh installation | PASS | Package resources, base imports, gateway coverage command and connector entry point |

Three existing failures originate in `socket(AF_UNIX)` returning `EPERM`:

- `test_guest_engine.test_private_paired_channels`
- `test_hardening_additions.test_bind_private_unix_socket_mode_and_dir`
- `test_hardening_additions.test_accept_authenticated_rejects_foreign_uid`

The fourth, `test_hardening_additions.test_bounded_sandbox_output_kills_flooding_workload`,
fails because the sandbox emits no backend attestation. A direct host probe
confirmed `unshare: write failed /proc/self/uid_map: Operation not permitted`.
These are retained as failures, not converted into passing security results.

The new production-method tests replace host certification and the final OS
effect with explicit recording fixtures. They check actual authorized argv,
effect counts, policy verdicts and absence of effects for rejected inputs. They
do not certify a kernel boundary. The real stdio test uses the pinned SDK; it
does not launch Codex or Claude. The separate live runner is
`tools/qualify_agent_gateway.py`.

The wheel was built without modifying the committed source. Its fresh base
installation includes the connector command but deliberately does not install
the optional MCP dependency. The handler and stdio tests ran in a test
environment with the pinned extra installed.

No new KVM, physical hardware approval, managed agent, production-image or
independent-review result is claimed. Enterprise gates remain `UNQUALIFIED` in
`src/bulldog/data/agent_gateway_release.json`. See
[the implementation guide](../../AGENT_GATEWAY.md) for deployment requirements.

`validation.json` contains the source and artifact hashes. The JUnit digest is
an identifier for the locally generated full report; it is not a signature or
independent attestation.

## Operator-reported Codespaces run

The operator subsequently supplied a terminal transcript from published commit
`4ce6a475d34d6a3529c7f77de31aaaa916d3c82b`: **71 passed in 3.87 seconds**,
with no failures or skips in the six-file gateway/router subset. This includes
the two real Unix IPC tests that were skipped in the authoring environment.
The transcript identifies MCP 2.2.0 and pytest 9.1.1. The private JUnit report
was not independently retrieved or hashed here. These are source/protocol and
local IPC results; the stdio authority and final HTTP effect remain explicit
test fixtures. They do not constitute a connected production deployment.

`tools/run_codespace_agent_gateway.py` now prepares a separate bounded live host
test. Its evidence acceptance tests require matching argv, a zero exit code,
one matching audit result and a valid current collector receipt. A run in the
authoring environment remained **BLOCKED**: only UID 0 is mapped, Unix sockets
are forbidden, and user namespace creation is denied. This is not converted to
a live PASS. The runner requires a real operator-configured external collector
and retains its own `report.json` for subsequent review.

Runner-focused regression in the authoring environment: **85 passed, 2 skipped**
in 2.33 seconds, including the original gateway subset and 16 new evidence and
cleanup checks. The skips remain the two live Unix socket tests. The system
Python also imported the authority without the optional MCP dependencies. These
checks do not validate sudo provisioning or live cross-account execution here.

## Collector configuration handoff

The operator's transcript from published commit
`5efa61eac9d8d5233c972a55c6be9a564ceb3f44` reports all four initial host checks
passing: a non-root operator, Unix sockets, Linux namespaces and cgroup v2.
The live run then stopped at collector selection. A separate existence check
found that the previously recorded collector key path was absent from that
Codespace. No production tool execution or authenticated receipt is claimed.

The runner now supports explicit `--collector-from-env` selection of the
documented Codespaces inputs, including the Worker name `BULL_ANCHOR_MASTER_KEY`
as a key alias. Configuration reports contain presence flags and bounded BULL
state paths, not key values. The runner preserves exact key bytes, refuses
conflicting inputs, and never creates or rotates a remote collector credential.

Focused regression: **96 passed, 2 skipped** in 2.44 seconds. Eleven additional
checks cover explicit selection, read-only preflight, secret redaction, exact
byte preservation, private file creation without overwrite, conflicting inputs,
missing inputs, the Worker-name alias, local URL rejection and path discovery.
The skipped Unix socket cases have the same authoring-host restriction as above.
The collector configuration fixtures are synthetic; live qualification remains
pending the operator's matching collector credential and a successful real run.
