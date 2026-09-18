# BULL Pages site

This directory is the public static GitHub Pages surface for BULL. It is deliberately outside the trusted Linux enforcement boundary.

## Site direction

The homepage is a long-form technical explainer rather than a fake SOC dashboard. A visitor can read the problem, trust model, examples, architecture, browser-versus-host boundary, multi-agent design, brokers, limitations, developer surface, and build evidence in one scroll.

Only the parts that genuinely need interaction remain interactive.

## Real browser policy core

The public lab loads the deployed copies of:

- `src/bulldog/models.py`
- `src/bulldog/canonicalizer.py`
- `src/bulldog/policy.py`
- `src/bulldog/session_guard.py`

Pyodide executes those Python sources locally in the visitor's browser.

Session counters, alerts, charts, and event rows start at zero and are populated only by actions actually evaluated during that browser session.

## Linux enforcement boundary

GitHub Pages does not claim to run namespaces, seccomp, Landlock, cgroups, malware scanning, secret brokers, pinned egress, or arbitrary visitor code. Those controls require a separately deployed BULL Linux host boundary.

## Hosted model connector

The optional hosted-model section asks a visitor-selected OpenAI-compatible endpoint for one bounded action proposal and sends that proposal through BULL's browser policy core. The model response remains untrusted data and is never executed as a shell command by the public page.

See `docs/HOSTED_OPEN_MODEL_CONNECTOR.md` in the repository.

## Deployment

`.github/workflows/pages.yml` verifies BULL before publishing. The Pages artifact is uploaded only after the regression suite, local-host red-team tests, TLA+ model check, frontend contract checks, exact-source copy checks, and browser-core self-tests succeed.

## Local preview

The deployed artifact is assembled by the Pages workflow because it copies current BULL policy sources into `runtime/bull_core/`. A bare static server from a fresh checkout does not exactly reproduce the deployed artifact until the same source-copy build step is performed.
