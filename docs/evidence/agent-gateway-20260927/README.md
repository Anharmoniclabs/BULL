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
