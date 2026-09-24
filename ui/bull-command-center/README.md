# BULL Command Center

Local interface prototype for **BULL — Blocking Unauthorized Logic Loopholes**.

This is the full BULL desktop/dashboard concept. Agent Scan is one view inside the
system, alongside repository/workspace inspection, policy evaluation, trace
visualization, assurance/compliance evidence, authenticated audit logs,
AgentSentinel, adversary/swarm correlation, malware admission scanning, runtime
configuration, and the approved BULL brand pack.

The browser is an interface layer. Enforcement stays in BULL's existing runtime
and authority paths.

## Codespaces

```bash
cd /workspaces/BULL
git fetch origin
git switch ui/bull-command-center-v1
PYTHONPATH=src python ui/bull-command-center/dashboard_server.py --port 8000
```

Open port **8000** from the Codespaces Ports panel.

Or run:

```bash
bash scripts/launch-command-center.sh
```

## Wired views

- **Main** — aggregated BULL status, live audit window, repo state, control
  evidence and observed adversary/swarm registry.
- **File / Repo** — actual Git branch/commit/status plus a bounded repository
  text-file browser.
- **Working Folder** — repository-root workspace view and the real bounded
  `MalwareScanner` path when ClamAV is installed.
- **Visualization** — BULL component topology, real deterministic policy
  evaluation and runtime trace-model simulation.
- **Controls / Compliance** — actual `evaluate_assurance()` control results.
- **BULL Logs** — verification and recent records from `BULL_AUDIT_LEDGER`.
- **Agents / Models** — actual `AgentSentinel`, passive artifact discovery,
  BULL `AdversaryRegistry` swarm clustering and quarantine classification.
- **Settings / Brand** — deployment/configuration presence and every asset from
  `site/assets/brand/manifest.json`.

## Brand source

The UI serves the existing approved BULL pack directly from
`site/assets/brand/`; it does not invent or redraw a replacement logo.

## Safety boundary for interface testing

There is intentionally no generic shell endpoint, arbitrary file write, Git
push, policy bypass, approval bypass, or unrestricted command execution endpoint.
Policy evaluation and trace simulation are real BULL code paths but do not execute
the requested operation. Malware scan targets are restricted to files inside the
repository. Public URL agent discovery is passive, text-only, size-bounded and
blocks local/private/reserved destinations.

Buttons that later perform consequential changes should be routed through BULL's
existing dispatcher/approval/authority mechanisms rather than browser-granted
authority.


## Real KVM runtime view

The **Runtime / VM** page is wired to the repository's actual KVM/deployment
paths, not a simulated VM status card.

For the five-case KVM runner, export the verified asset manifest used by BULL:

```bash
export BULL_DEPLOYMENT_ASSETS="$HOME/bull-guest-release/assets-local.json"
```

Then start the command center. The Runtime / VM page calls the real
`tools.deployment_check.probe_kvm()`, validates the manifest with
`checked_assets()`, and can launch `microvm/integration.py` for one selected
case or all five cases. Logs and evidence paths are surfaced in the UI.

To validate a private raw launcher configuration without booting it:

```bash
export BULL_MICROVM_CONFIG_FILE="/absolute/private/path/deployment.env"
```

The **Validate configured launcher** button invokes BULL's
`microvm/run-bull-microvm.sh --print-command` path. The full deployment check
button invokes `tools/deployment_check.py` in a background job. Optional
`BULL_TLA_JAR` and `BULL_DEPLOYMENT_STATE` are forwarded when configured.

BULL's current supported MicroVM architecture is intentionally a **one-shot
Linux/KVM guest**. The repository explicitly defers persistent VM sessions, so
the dashboard does not misrepresent it as a continuously running desktop Linux
VM. When KVM or verified guest assets are missing, the UI reports BLOCKED rather
than substituting software emulation or fake success.
