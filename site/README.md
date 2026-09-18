# BULL Pages site

This directory is the static GitHub Pages surface for BULL. It is deliberately outside the trusted BULL runtime and must never receive deployment secrets, cloud credentials, a Docker socket, or the ability to execute uploaded code.

## One public console

- `index.html` is the BULL Control dashboard and Playground.
- `control-center.html` only redirects to `index.html` so old links do not open a second, conflicting implementation.

There is no separate hand-written policy simulator. The public Playground loads the exact deployed copies of:

- `src/bulldog/models.py`
- `src/bulldog/canonicalizer.py`
- `src/bulldog/policy.py`
- `src/bulldog/session_guard.py`

Pyodide executes those Python sources locally in the visitor's browser.

Dashboard counters, alerts, charts, and event rows start at zero and are populated only by decisions actually evaluated during that browser session. GitHub Actions build evidence is generated during deployment.

## Linux enforcement boundary

GitHub Pages does not claim to run namespaces, seccomp, Landlock, cgroups, malware scanning, secret brokers, pinned egress, or arbitrary visitor code. Those require a separately deployed BULL Linux host boundary.

## Preview locally

```bash
cd site
python -m http.server 8080
```

Open `http://localhost:8080/`.

## Deployment

`.github/workflows/pages.yml` verifies BULL before publishing. The Pages artifact is uploaded only after the regression suite, local-host red-team tests, TLA+ model check, frontend contract checks, exact-source copy checks, and browser-core self-tests succeed.
