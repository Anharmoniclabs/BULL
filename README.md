# BULL

**BULL** is an experimental open-source AI execution firewall and defensive runtime for local agents.

The core rule is simple:

> Untrusted data can influence an agent, but it must never automatically become execution authority.

BULL is designed to sit between AI systems and sensitive host capabilities such as the filesystem, shell, network, credentials, subprocesses, repositories, APIs, and other agents.

## Goals

- Treat webpages, files, model outputs, tool results, and agent-to-agent messages as untrusted inputs.
- Track provenance and taint across decisions.
- Enforce deterministic capability boundaries.
- Prevent privilege inheritance beyond a parent agent's authority.
- Detect canary/honeypot access.
- Fail closed when policy cannot be resolved.
- Keep the learned model advisory rather than authoritative.
- Produce tamper-evident audit records for every decision.

## Architecture

```text
External input
     |
     v
Ingress / provenance labeling
     |
     v
Agent proposes action
     |
     v
BULL policy gate
 |       |        |
allow  sandbox   deny
                 |
                 v
             human review
```

## Current prototype

The first prototype contains:

- deterministic policy engine
- capability model
- provenance/taint model
- agent delegation checks
- credential and canary protections
- advisory small-model interface
- hash-chained audit ledger
- CLI demo
- unit tests

## Status

Research prototype. Not yet a hardened endpoint-security product. Do not rely on it as the sole control protecting production systems.

## Research direction

BULL is intended to test whether a small specialized execution-governance model, paired with deterministic controls, can safely constrain much larger autonomous agents.

Key hypothesis:

```text
control intelligence << generation intelligence
```

The long-term target is a model-agnostic host defense layer for AI agents.
