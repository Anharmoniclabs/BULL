# Local MCP audit profile: validation record

Date: 2026-09-27. This records source and protocol checks, not a live protected
agent deployment. The local profile needs no external service credentials.

The staged tree tested before this record was added was
`651e077b12a73e21bc0505b0550708ceea1216d8`.
Its runtime file-manifest SHA-256 was
`39bc6d995a827dd9f50daaed063b59480ec5bc9ab72fdf114948b96156a15f65`.

## Changes checked

- LocalRuntime and LocalDispatcher share the strict runtime's command binding,
  policy checks, execution permits, resource budgets and sandbox requirements.
- LocalEffectRouter accepts fixed process execution only. Network and secret
  brokers remain unavailable in this profile.
- Installation creates independent private keys and an authenticated empty audit
  checkpoint. Missing, tampered, stale and wrong-key checkpoints block appends.
- Local setup neither discovers nor inherits external collector credentials.
- Production runtime/router type checks reject the local profile. Qualification
  checks the selected profile and reports `LOCAL TOOL PASS` separately.
- Gateway adversarial fixtures exercise both profiles: spoofed argv/authority,
  wrong UID, revocation, executable changes, call budgets and uncertain outcomes.
  These fixtures replace host certification and final OS execution; they do not
  establish containment.
- The bounded live runner waits for final socket ownership and permissions, uses
  distinct accounts and checks retained audit against the observed MCP result.

## Results in the editing environment

```sh
python -m pytest -q -ra --junitxml=/tmp/bull-local-gateway-final-regression.xml
```

813 passed, 21 subtests passed, 2 skipped, 4 failed. The JUnit report SHA-256 was
`53cfbe659833427d0ce46324c6a326ac66d0476327705d08e22dc7f3d040c072`.

The four failures were `test_private_paired_channels`,
`test_bind_private_unix_socket_mode_and_dir`,
`test_accept_authenticated_rejects_foreign_uid`, and
`test_bounded_sandbox_output_kills_flooding_workload`. This environment denies
Unix socket creation and namespace startup. Two other live IPC checks explicitly
skipped for the same socket restriction. The full suite is therefore not green.

The local preflight ran here and reported: non-root operator false, Unix sockets
false, Linux namespaces false, cgroup-v2 true, local audit selected true, external
collector required false. It correctly remained `BLOCKED`.

## Live evidence still required

On a supported Linux operator host, from a clean reviewed checkout:

```sh
python3 tools/run_local_agent_gateway.py --install-deps
```

Expected successful label: `LOCAL TOOL PASS`. Real namespace enforcement, distinct
UID IPC and malware scanning must pass there before that result can be recorded.
No live Codex/Claude session, KVM result, external audit receipt, multi-day soak,
hardware approval or independent review is claimed by this change. Native agent
tools remain outside the connected gateway. Host administrators remain trusted.

## Runner startup correction

An operator run at `91718b73a372692b263a7db169cce3dc53885814` reached local
authority startup, then reported `BLOCKED` with an integer/string `TypeError`.
The directory-creation loop had overwritten the audit profile with a permission
number. The runner now keeps `audit_mode` and `directory_mode` separate.

Six regression cases exercise the worker through success, failed authority
startup and a mismatched client profile, for both local and external audit.
They validate real retained audit records and check cleanup of simulated
processes and accounts. Privileged operations and MCP children are simulated;
these tests cannot establish live isolation or an external collector receipt.

The focused regression command was:

```sh
python -m pytest -q -ra --tb=short \
  tests/test_live_gateway_qualification.py tests/test_local_gateway.py \
  tests/test_agent_gateway.py tests/test_gateway_broker_boundary.py \
  tests/test_gateway_transport.py tests/test_mcp_gateway_sdk.py \
  tests/test_mcp_stdio.py tests/test_production_router.py \
  tests/test_full_argv_and_production_wiring.py tests/test_deployment_setup.py \
  --junitxml=/tmp/bull-gateway-runner-regression.xml
```

Result: 202 passed, 2 skipped. Both skips require Unix IPC, which this editing
environment prohibits. The JUnit SHA-256 was
`a1312ecf5999fda8a83cd633ed8187f16a1b83a277f98f4d64a6496a80bc4117`.
The corrected runner still needs a live operator-host result.
