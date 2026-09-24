# BULL Command Center — interface prototype

This is the **full BULL dashboard prototype**, not an Agent Scan-only product. Agent Scan is one panel in the larger interface.

The local adapter reads existing BULL components for interface testing:
- Git repository / working-folder state
- AgentSentinel detection state
- BULL assurance/control registry
- audit-ledger verification when `BULL_AUDIT_LEDGER` is configured
- ClamAV scanner availability
- signed-policy configuration state
- MicroVM configuration state
- remote audit-anchor configuration state

It does not move enforcement into the browser. BULL remains the enforcement boundary; the dashboard is an observability/control surface.

## Codespaces

```bash
cd /workspaces/BULL
git fetch origin
git switch ui/agent-scan-command-center
PYTHONPATH=src python ui/agent-scan/dashboard_server.py --port 8000
```

Open port **8000** in the Codespaces Ports panel. The dashboard refreshes live system state every five seconds.

## Agent Scan experimental panel

Pasted HTML/text can be inspected in-browser. The separate `scan_proxy.py` helper is available for constrained passive public-URL fetching:

```bash
python ui/agent-scan/scan_proxy.py --port 8765
```

Its matches are evidence indicators, not automatic attribution. The global-map concept must only display coordinates when an observation has defensible location evidence; the prototype radar intentionally avoids fabricating geographic data.

## Interface safety

The adapter is read-mostly. It does not provide browser endpoints for arbitrary shell execution, policy mutation, Git push, approval bypass, MicroVM launch, or firewall changes. Those controls should be added individually through BULL's existing authority/approval paths rather than by giving the dashboard a generic command endpoint.
