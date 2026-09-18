# BULL Pages site

This directory is the static GitHub Pages surface for BULL. It is deliberately outside the trusted BULL runtime and must never receive deployment secrets, cloud credentials, a Docker socket, or the ability to execute uploaded code.

## Routes

- `index.html`: existing BULL Playground landing experience.
- `control-center.html`: browser-only security decision laboratory.

The control center evaluates deterministic scenario requests in the visitor's browser and generates a local SHA-256 hash of each report. It is a policy-model simulation, not a remote sandbox attestation or live security telemetry.

## Preview locally

```bash
cd site
python -m http.server 8080
```

Open `http://localhost:8080/control-center.html`.

## GitHub Pages deployment

The workflow `.github/workflows/pages.yml` publishes `site/` after a successful push to `main`. In repository settings, open **Settings → Pages** and choose **GitHub Actions** as the source.

## Live runner boundary

A live workload runner must be hosted separately. It needs independently managed authentication, quotas, rate limits, disposable compute, no ambient credentials, no default network egress, bounded output, and BULL strict Linux inside the outer isolation boundary. Do not add arbitrary-code execution to GitHub Pages.
