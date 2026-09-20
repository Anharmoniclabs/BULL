# BULL Cloudflare audit anchor

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

## 3. Create one master key

Keep the same exact printable bytes on the BULL host and in the Worker secret.

```sh
install -d -m 700 ~/.local/share/bull-production/secrets
openssl rand -hex 32 | tr -d '\n' > ~/.local/share/bull-production/secrets/cloudflare-anchor.key
chmod 600 ~/.local/share/bull-production/secrets/cloudflare-anchor.key
cat ~/.local/share/bull-production/secrets/cloudflare-anchor.key | npx wrangler secret put BULL_ANCHOR_MASTER_KEY
```

Never commit the key.

## 4. Deploy

```sh
npm run deploy
```

Wrangler prints a `workers.dev` URL. The BULL endpoint is:

```text
https://YOUR-WORKER.workers.dev/v1/checkpoints
```

The Worker accepts only authenticated POST checkpoints on that route, enforces session/sequence/head continuity in D1, permits only an exact retry of the latest committed frame, and returns a BULL-compatible authenticated acknowledgement.

## 5. Provision the BULL host

```sh
curl -fsSL https://raw.githubusercontent.com/Anharmoniclabs/BULL/main/tools/bull-production-provision.sh -o bull-production-provision.sh
chmod +x bull-production-provision.sh

./bull-production-provision.sh \
  --anchor-url https://YOUR-WORKER.workers.dev/v1/checkpoints \
  --anchor-key-file ~/.local/share/bull-production/secrets/cloudflare-anchor.key
```

A successful run must include:

```text
authenticated remote audit acknowledgement: PASS
ProductionRuntime: PASS
ProductionDispatcher: PASS
BULL production provisioning: PASS
```

## Security scope

This is an external durable anchor, not a replacement for the local BULL ledger or the KVM boundary. Cloudflare account compromise remains part of the external service trust surface. The Worker does not receive prompts, credentials, or workload payloads from BULL's direct HTTPS checkpoint transport; it receives the session, monotonic sequence, previous/head hashes, and MAC.

Do not use localhost, a test CA, or a committed key for production verification.
