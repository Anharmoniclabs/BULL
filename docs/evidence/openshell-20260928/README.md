# BULL × NVIDIA OpenShell v0.1.2 — experiment evidence (2026-09-28)

Produced by `tools/openshell_experiment.py` against a live OpenShell gateway
built from source (tag v0.1.2, commit 6648bd0), Docker driver. Phase A is
OpenShell only; phase B registers BULL's supervisor middleware and gateway
interceptor fail-closed. Write-up:
[`docs/papers/BULL_OPENSHELL_COMPOSITION_20260928.md`](../../papers/BULL_OPENSHELL_COMPOSITION_20260928.md).

| File | Contents |
|---|---|
| `results.json` | Every case (expected, observed, pass, evidence), versions, latency summary, `gateway info` |
| `cases.csv` / `latency.csv` / `latency-raw.json` | Tabulated results and raw per-request samples (ms) |
| `correlation.json` | C10: each BULL decision joined to OpenShell OCSF events and upstream effects |
| `bull-audit.jsonl` | BULL hash-chained ledger (phase B, includes the 400 latency requests) |
| `ocsf-<sandbox>-<phase>.txt` | OpenShell OCSF shorthand from `openshell logs` |
| `upstream-receipts-<phase>.json` | Requests the destination services actually received during the cases |
| `gateway-<phase>.toml` / `.log`, `bull.log`, `policy.yaml` | Configuration and process logs |

Temporary paths in the TOML (`/tmp/bull-os-*`) were per-run scratch
directories; the JWT keys there were generated per run and are not included.
No credentials appear in this directory (the C6 canary was checked absent).
