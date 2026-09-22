# BULL Cloudflare audit anchor

The portable provisioner is `tools/deployment_setup.py`; the optional
`tools/bull-production-provision.sh` wrapper accepts the same commands.

Free external HTTPS audit-anchor deployment for BULL using Cloudflare Workers + D1.

## 1. Create the project and database

```sh
cd deploy/cloudflare-audit
npm install
npx wrangler login
npx wrangler d1 create bull-audit-db --location enam
```

Copy the returned D1 `database_id` into `wrangler.jsonc`.

## 2. Initialize durable storage

```sh
npm run db:init
```

## 3. Use your installation's independently generated key

First initialize private deployment state from the repository root using
`tools/deployment_setup.py init`, as described in the
[portable deployment guide](../../docs/REPRODUCIBLE_DEPLOYMENT.md).
Set `BULL_STATE` to that directory, then from this collector directory:

```bash
npx wrangler secret put BULL_ANCHOR_MASTER_KEY < "$BULL_STATE/secrets/collector.key"
```

The generated key contains printable bytes with no trailing newline. It belongs
only to your deployment. No author's account or secret is required. For an
existing collector, initialize with `--existing-collector-key` and preserve its
exact bytes instead of rotating the service key. Never commit or print the key.

## 4. Deploy

```sh
npm run deploy
```

Wrangler prints a `workers.dev` URL. The BULL endpoint is:

```text
https://YOUR-WORKER.workers.dev/v1/checkpoints
```

The Worker accepts only authenticated POST checkpoints on that route, enforces session/sequence/head continuity in D1, permits only an exact retry of the latest committed frame, and returns a BULL-compatible authenticated acknowledgement.

## 5. Connect and validate your BULL installation

From the repository root, after deploying your own service:

```bash
.venv/bin/python tools/deployment_setup.py configure --state "$BULL_STATE" \
  --collector-url https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/v1/checkpoints

.venv/bin/python tools/deployment_check.py --deployment "$BULL_STATE" \
  --tla-jar "$HOME/bull-tla2tools-v1.7.4.jar" \
  --output "$HOME/bull-evidence-$(date -u +%Y%m%dT%H%M%SZ)"
```

`external_collector_host: PASS` requires a real authenticated response. The
separate guest/external gate also requires verified VM assets and all current KVM
cases. Missing prerequisites stay BLOCKED. Follow the full portable guide for
host delegation, guest builds and physical-key enrollment.

## Security scope

This is an external durable anchor, not a replacement for the local BULL ledger or the KVM boundary. Cloudflare account compromise remains part of the external service trust surface. The Worker does not receive prompts, credentials, or workload payloads from BULL's direct HTTPS checkpoint transport; it receives the session, monotonic sequence, previous/head hashes, and MAC.

Do not use localhost, a test CA, or a committed key for production verification.

## Workers Builds root-directory errors

This repository's root is a Python project, not a Worker entry point. The audit
Worker package and Wrangler configuration live in `deploy/cloudflare-audit/`;
its checked-in Worker name is `bull-audit` and its entry point is `src/index.ts`
relative to that directory. A root-directory trigger running
`npx wrangler versions upload` without a selected configuration fails with
“Missing entry-point to Worker script or to assets directory”. Installing the
Python package does not supply that entry point.

For an audit Worker build, select `deploy/cloudflare-audit` as the trigger root
and ensure the dashboard Worker name matches the selected Wrangler configuration.
Alternatively, an operator can explicitly select that config with Wrangler's
`--config` option. Before any upload, replace the D1 placeholder in the operator's
configuration with the intended existing database binding; retain the existing
collector secret. Do not point an unrelated Worker at this package or create a
new production identity just to make CI green.

The engineering website is built by `tools/build_site.py` and published through
GitHub Pages. Its PR workflow deliberately skips the deployment job. A separate
Cloudflare website mirror needs its own explicit assets configuration and build
output; the audit Worker configuration is not a website configuration.

Cloudflare documents [trigger root directories](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/)
and [matching Worker names](https://developers.cloudflare.com/workers/ci-cd/builds/).
A diagnosed trigger error is not a successful build: retain the failed status
until the intended configuration has been selected and an authorized build
actually passes. No upload or production configuration change is required to
review or test this repository locally.
