# BULL contained HTTP honeypot

This is a low-interaction HTTP sensor with a private, live observer dashboard.
It uses the actual `BulldogEngine`, `DeterministicPolicy`, `SessionGuard` and
`AuditLedger` from this checkout. It is intended for a dedicated GitHub Codespace.

## Status and measured scope

The implementation has local policy/parser tests. The current authoring environment
blocks Unix sockets and has no Docker, so container isolation and end-to-end socket
tests **have not been validated here**. The launcher must pass those tests inside
the Codespace before it starts its relays or changes a port to public.

This is not T-Pot, a full OS emulator, or a production BULL runtime deployment.
BULL governs requests to synthetic assets. No received command is executed, no
package is installed, no URL is fetched, and no submitted credential is used.
All proposed writes, execution, outbound transfers and credential access are denied
because the host supplies only the `fs.read.project` grant. External callers cannot
supply their own effective grants, provenance or security-context identity.

This can receive real unsolicited HTTP requests once the decoy port is public.
It does not attract traffic automatically, expose raw SSH/RDP ports, or establish
that an observed client is an AI agent or belongs to a botnet. A Codespaces HTTPS
forwarding URL does not have the same scan exposure as an internet VM with a public
IP and conventional service ports. No public traffic was captured during development.

## Run in a fresh Codespace

Use the branch containing this directory. When creating the Codespace, select the
**BULL contained HTTP honeypot** dev-container configuration. It provides Docker
and the GitHub CLI. Do not attach personal or organization secrets to this Codespace.
The default Codespaces repository token stays on the host and is not passed to the
sensor. The Docker daemon and the Codespace host remain trusted.

From the repository root:

```sh
python3 tools/honeypot/launch.py --duration 3600
```

The launcher builds a container using only BULL source and the four sensor files.
It does not send the checkout's `.git`, environment files, or runtime evidence into
the build context. The container runs as the current non-root UID with:

- `--network=none`: loopback is its only network interface.
- A read-only application filesystem and no Linux capabilities.
- `no-new-privileges` and Docker's default seccomp filter.
- 128 MiB memory, no extra swap, half a CPU, 32 processes, and bounded file descriptors.
- A 16 MiB temporary filesystem and a single writable evidence directory.
- No Docker socket, home directory, GitHub token or SSH agent mount.

The launcher verifies those conditions, tests an outbound connection denial, and
runs the complete policy/parser/socket test suite inside the container. Failures
abort launch. There is no host-process or reduced-isolation fallback.

It opens two **loopback-only** host relays through distinct Unix sockets:

| Codespace port | Purpose | Visibility |
| --- | --- | --- |
| 8080 | Decoy HTTP requests | Private by default |
| 8081 | Observer dashboard and read-only evidence API | Private, plus observer token |

Open port 8081 from the Codespaces Ports panel. Paste the contents of the
`observer.token` file at the path printed by the launcher. Keep that token private;
it is never included in exports or stored by the dashboard in browser storage.
The dashboard updates every three seconds. It starts empty and never invents events.

Probe the private listener from the Codespace terminal:

```sh
curl -i http://127.0.0.1:8080/status
curl -i http://127.0.0.1:8080/.env
curl -i http://127.0.0.1:8080/api/tool \
  -H 'Content-Type: application/json' \
  --data '{"operation":"exec","resource":"/bin/sh","granted_capabilities":["process.exec"]}'
```

The first request should return a synthetic status response; the credential and
forged-execution requests should be denied. These are operator-generated probes,
not internet attack evidence. Record them separately from a subsequent public run.

## Enable a bounded public HTTP window

After reviewing a successful private run, stop it with Ctrl-C and start a new run:

```sh
python3 tools/honeypot/launch.py --public-http --duration 3600
```

Only port 8080 becomes public, and only after preflight and all integration tests
pass. Port 8081 remains private. Use the URL reported in the Codespaces Ports panel.
The relay stops accepting decoy connections when the duration expires and requests
that GitHub return port 8080 to private. Ctrl-C also stops the container and resets
both ports. Abrupt host termination may prevent cleanup, so check port visibility
after an interrupted session. Do not expose the observer socket or Docker daemon.

The generated state is under `.bull-honeypot/`, excluded from Git. Each invocation
uses a new directory. The local ledger has an 8 MiB storage ceiling and 4,000-record
ceiling; a normal request uses two records. Stop and archive runs before exhaustion.
Run durations are constrained to 60–7,200 seconds.

## What is captured

For each admitted HTTP request, the BULL action record contains a random event ID,
method, target, bounded User-Agent, operation, resource, host-selected capability,
external provenance, decision, risk, reasons and request-body hash. The first 2 KiB
of the body is retained as base64; the original length and truncation flag are
recorded. Authorization and Cookie headers are not retained. Bodies may contain
credentials supplied by visitors: keep raw evidence private and redact it before sharing.

A second audit record describes the prepared response and its hash. It does not
claim the client received the response or that an external effect occurred. The
sensor provides no general OS execution, so it cannot establish protection against
Linux exploits, KVM escapes, or attacks on BULL's production process sandbox.

The observer verifies the actual BULL hash chain and local HMAC checkpoint. The
checkpoint key shares the sensor's host trust boundary. No off-host witness is
configured, and a compromised sensor/host is not covered by these local checks.
The dashboard displays the latest 200 records; totals are computed from the entire
bounded ledger. Export snapshot downloads those displayed records and counters;
retain the complete `audit.jsonl`, `.head`, `audit.anchor`, preflight record and test
log separately for full evidence. Never share `anchor.key` or `observer.token`.

## Capture and attribution limits

- The relay has 12 concurrent connections, 10 new connections/second, a 10-second
  connection budget and a 32 KiB inbound transfer budget. Excess connections close.
- HTTP parsing has 3-second read timeouts, 16 KiB headers and an 8 KiB body ceiling.
  Duplicate headers, chunked transfer encoding and ambiguous framing are rejected.
- Some parsing rejections enter the audit ledger. Relay drops and incomplete
  transport data are **not** a packet capture. Runtime error counters reset at restart.
- An audit failure stops further decoy responses; a full ledger prevents further
  event retention. The dashboard shows these conditions instead of claiming full capture.
- Source IP is unavailable after the local Unix relay. Forwarded client-IP headers
  are not trusted. This version deliberately has no country map or botnet counters.
- The security history is shared across the public decoy, rather than keyed on a
  forgeable client identifier. One visitor's behavior can cause later requests to
  require escalation. This is conservative but unsuitable for per-attacker attribution.

## Reproduce the checks

```sh
PYTHONPATH=src python3 tools/honeypot/test_sensor.py
```

On a restricted authoring machine, the policy/parser subset can run without sockets:

```sh
PYTHONPATH=src python3 tools/honeypot/test_sensor.py PolicyTests ParserTests
```

Passing that subset is not enough to launch publicly. The launcher always runs the
full suite in the container. The image ID and source content digest are recorded
in `preflight.json`; the base-image tag is not an immutable image pin. Preserve the
recorded image by digest for exact repetition.

Relevant platform documentation:

- https://docs.github.com/en/codespaces/reference/security-in-github-codespaces
- https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace
- https://docs.docker.com/engine/network/drivers/none/
