# Audit anchor service

The anchor is a separate service that retains audit evidence after a guest
shuts down. The host retains the remote service credential. Guest relay
messages contain a session ID, sequence, complete hash-chained record, and MAC;
they cannot select an endpoint, request headers, or host filesystem paths.

Implemented here: a bounded SQLite checkpoint service, direct HTTPS transport,
relay framing and host relay components, and integration of direct HTTPS with
ProductionRuntime. Guest bootstrap/port provisioning and production relay
activation remain unfinished. Production rejects relay mode until that trusted
bootstrap exists; no dummy HTTPS configuration is used.

## Local TLS test

Install BULL in your Python environment, then run:

```sh
microvm/audit/local-test.sh /path/to/new-private-test-directory
```

The script refuses an existing directory and generates test-only keys and a
one-day localhost certificate. It runs in the foreground on loopback port
9443. In tests, pass the certificate explicitly as `test_ca` to
`HTTPSAnchorTransport`; that transport reports `production_ready=False`.
Localhost and configured test CAs cannot satisfy production readiness.

`python -m pytest -q tests/test_anchor_service.py` includes a real loopback TLS
fixture, durable restart, conflicting records, bad authentication, frame and
storage bounds, exact retries, lost acknowledgements, and explicit recovery.
These are service tests, not MicroVM boot evidence.

## Production deployment recipe

1. Install the reviewed BULL release in a dedicated service environment.
2. Create an owner-only state directory on persistent storage. Provision a
   random key of at least 32 bytes through your secret manager into an
   owner-only regular file. Do not use local test keys or commit keys to Git.
   For the environment-based direct client, use at least 32 bytes of random
   printable text and preserve the exact same bytes in the service key file
   and client secret (without adding a trailing newline).
3. Run the following under a dedicated non-root service account with automatic
   restart and a read-only application installation:

   ```sh
   python -m bulldog.anchor_service \
     --database /var/lib/bull-anchor/audit.sqlite \
     --key-file /run/secrets/bull-anchor-key --port 9443
   ```

4. Put an HTTPS reverse proxy with a valid deployment certificate in front of
   `127.0.0.1:9443`. Expose only `POST /v1/checkpoints`, set a 64 KiB body limit
   and short request/read timeouts, disable response caching, and rate-limit
   connections. Keep the backend port loopback-only. A minimal Nginx location
   inside a separately configured TLS server is:

   ```nginx
   location = /v1/checkpoints {
       limit_except POST { deny all; }
       client_max_body_size 64k;
       client_body_timeout 5s;
       proxy_connect_timeout 5s;
       proxy_read_timeout 10s;
       proxy_pass http://127.0.0.1:9443;
   }
   ```

5. Supply the same master credential to the trusted direct client through the
   existing `BULL_REMOTE_AUDIT_ANCHOR_KEY` deployment environment and set
   `BULL_REMOTE_AUDIT_ANCHOR_URL=https://YOUR_DEPLOYMENT/v1/checkpoints`.
   The host must generate a fresh random 64-character hex
   `BULL_AUDIT_SESSION_ID` for each new session. A restored ledger must retain
   its original session ID and key. Per-session keys are derived with HMAC;
   acknowledgements bind the session, sequence, hash, and message direction.
   Long-lived credentials must never be placed in workload environments.
6. Verify durable writes, restart recovery, certificate validation, and backup
   restoration on the actual deployment before declaring it production ready.

SQLite uses synchronous FULL transactions. The service acknowledges only after
the transaction commits. The remote service retains authenticated checkpoint history, without prompts
or workload payloads. The host relay retains complete records locally. It
accepts an exact retry of the latest checkpoint; older replay, sequence gaps,
and conflicting history are rejected. Default storage is bounded to 256 MiB.
Exhaustion stops acceptance. Back up with SQLite's supported backup mechanism,
including consistent handling of WAL; do not copy only a live database file.

## Recovery and rollback

A missing acknowledgement leaves the ledger's remote checkpoint behind its
local head. The next append fails closed. Preserve the ledger, head,
checkpoint, host relay database, original session ID, and key. First verify
the local chain and inspect the remote service. Trusted operator code may call
`AuditLedger.reconcile_remote()` on a ledger assembled with its original
versioned transport. This retries only the latest checkpoint and never reruns
a command. A conflict remains a failure requiring investigation; do not erase
records or mint a new session ID to hide it.

For rollback, stop accepting new sessions, preserve evidence, and restore a
previously verified application/kernel/image set. Keep the audit database and
credentials available for verification. Do not downgrade a database format or
rewrite history to make an old release accept it. A deployed HTTPS endpoint,
credential provisioning, and an independently verified guest relay are still
release prerequisites, not outcomes of local TLS tests.
