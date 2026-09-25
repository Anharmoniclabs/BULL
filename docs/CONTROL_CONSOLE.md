# BULL Command / Control Console

The local console is an operator view over BULL's existing runtime. It is not a
replacement policy engine and it does not weaken production gates.

## One-command launch

```bash
python -m pip install -e .
bull up --workspace "$PWD"
```

`bull up` is the normal entry point. It creates a private per-workspace BULL
state directory, configures a local audit ledger and snapshot scratch when the
operator has not supplied explicit deployment values, finds an available
console port, starts discovery, starts the bounded ClamAV scan when available,
starts dynamic assurance, and opens the browser on a local desktop.

In GitHub Codespaces it binds to the Codespace network interface and prints the
authenticated forwarded `app.github.dev` URL instead of pretending
`127.0.0.1` is reachable from the user's browser.

Use `bull setup --workspace "$PWD"` to prepare and inspect the launch
environment without starting the server.

The lower-level command remains available:

```bash
bull console --workspace "$PWD"
```

The default bind is `127.0.0.1:11510`. In a Codespace, use a private forwarded
port explicitly:

```bash
bull console --host 0.0.0.0 --port 11510 --workspace /workspaces/BULL
```

Keep the forwarded port private. The console deliberately provides no arbitrary
shell endpoint, no environment dump, and no generic process-kill endpoint.

## What is live

On startup the console immediately begins read-only process/service discovery.
It initializes the real `MalwareScanner`; if `clamscan` is installed, a bounded
workspace scan is started in the background. It also starts the real assurance
evaluator with dynamic backend attestation unless disabled.

The dashboard reads the configured audit ledger, signed policy bundle,
capability ceiling, MicroVM host prerequisites, local process observations,
swarm correlations, assurance controls, and malware results. Missing deployment
inputs are shown as `BLOCKED`, `UNAVAILABLE`, or `NOT CONFIGURED`; they are never
replaced with demo counters.

The browser uses a small internal API to move structured data, but the operator
interface renders cards, tables, control states, evidence text, and timelines.
Raw JSON is not used as the human-facing interface.

## Operator actions

The interface exposes only bounded control operations:

- refresh process/service discovery;
- run a bounded ClamAV workspace scan;
- re-run dynamic assurance/attestation;
- verify the local audit hash chain;
- probe MicroVM readiness;
- evaluate a deterministic policy request without executing it.

Actual agent execution continues through BULL's dispatcher/runtime boundary.
Actual MicroVM launch continues through `bulldog.microvm`; opening the web
console does not silently start a privileged VM.

## Environment

The console consumes the same deployment environment already used by BULL,
including `BULL_AUDIT_LEDGER`, `BULL_POLICY_BUNDLE`,
`BULL_POLICY_BUNDLE_KEY`, and `BULL_MICROVM_*` inputs.

Optional console scan limits:

- `BULL_CONSOLE_SCAN_TIMEOUT` (default `180` seconds)
- `BULL_CONSOLE_SCAN_MAX_BYTES` (default `268435456`)
- `BULL_CONSOLE_SCAN_MAX_FILES` (default `10000`)


## Managed MicroVM control

When `BULL_MICROVM_CONFIG_FILE` points at a valid trusted deployment
configuration and KVM/QEMU readiness passes, the MicroVM page can start the
existing `bulldog.microvm` launcher. The browser never supplies a shell
command or QEMU arguments. The console can stop only the launcher process that
it started itself, and console shutdown also tears down that owned launcher.
An externally launched VM remains observation-only.

The command center is portable across supported BULL hosts, but the hardened
enforcement backend remains Linux/KVM-specific. Unsupported controls are shown
as unavailable or blocked rather than simulated.
