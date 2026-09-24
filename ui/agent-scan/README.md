# BULL Agent Scan Command Center

Experimental Codespaces UI derived from the BULL command-center concept.

Run:

```bash
cd /workspaces/BULL
python -m http.server 8000 -d ui/agent-scan
python ui/agent-scan/scan_proxy.py --port 8765
```

Open port 8000 in the Codespaces Ports panel.

The UI can scan pasted HTML/text without a helper. Enable **fetch public URL** to use the local helper.

## Current detector

This first pass extracts evidence for agent frameworks/agentic language, multi-agent orchestration/swarm language, botnet/C2 terminology, and API/webhook/endpoints. It emits the matched evidence rather than claiming that a host is malicious.

The safe-fetch helper is intentionally passive: public HTTP(S) only, text-like responses only, 1 MB maximum response, short timeout, no authentication, no exploit execution, and blocks private/loopback/link-local/reserved/multicast destinations.

Next stages should add normalized observations, graph correlation across observations, temporal clustering, confidence calibration, BULL audit-ledger ingestion, and real map coordinates only when supported by evidence.