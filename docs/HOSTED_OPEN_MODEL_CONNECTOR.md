# Hosted open-weight model connector

The BULL browser lab can test an externally hosted, open-weight model against
BULL's **real browser Python policy core**.

The BULL repository hosts no model, model weights, model proxy, shared API key,
or agent workload.

## Flow

```text
Browser
  → visitor-selected hosted OpenAI-compatible model endpoint
  → one bounded JSON action proposal
  → current BULL form
  → existing Pyodide Python evaluate_json()
  → BULL decision trace and browser telemetry
```

The model response is untrusted data. It is mapped into BULL's existing action
form and evaluated. It is never executed as a shell command.

## Connector fields

- **Hosted endpoint**: HTTPS OpenAI-compatible endpoint base, for example
  `https://model.example.com/v1`.
- **Model ID**: the provider's open-weight model identifier.
- **Optional visitor API key**: retained only in JavaScript memory for the open
  tab. It is not written to browser storage, URLs, analytics, GitHub Pages, or
  this repository.

The endpoint is expected to support:

```text
POST /v1/chat/completions
```

with an OpenAI-compatible response containing:

```json
{
  "choices": [
    {
      "message": {
        "content": "{\"action\":\"filesystem.read\",\"resource\":\"/workspace/README.md\",\"reason\":\"...\"}"
      }
    }
  ]
}
```

## Ollama

A remote Ollama deployment must expose an OpenAI-compatible chat-completions
endpoint, use TLS, and permit the exact Pages origin with CORS:

```text
[https://anharmoniclabs.github.io](https://anharmoniclabs.github.io)
```

Do not use wildcard CORS for an authenticated public model service. The model
host is responsible for its own authentication, TLS, rate limits, observability,
and abuse controls.

## Browser limits

- 30-second request timeout.
- 16,000-character model response cap.
- 300 requested completion tokens.
- Fixed proposal-action allowlist.
- Model cannot grant itself BULL capabilities.
- Current BULL capability grants and optional parent ceiling remain unchanged.
- No command proposal is executed.

## Important boundary

This tests whether an external model proposes actions that the actual BULL
browser policy engine allows, denies, or restricts. It is not a Linux sandbox
attestation and does not run model-generated code.

Real workload execution belongs only in separately authenticated disposable
infrastructure with BULL strict Linux inside an outer isolation boundary.
