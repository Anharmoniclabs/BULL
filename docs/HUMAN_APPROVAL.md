# Credentialed approval for consequential operations

Status: release-candidate implementation. Physical authenticator and production
end-to-end validation remain required. This feature is an additional constraint
on existing policy, not an override or a general permission to execute a shell.

## Supported boundary

ProductionDispatcher checks policy/domain authority first. It then requires a
fresh approval before scoped secret retrieval and network broker requests. Exact
HTTPS GET/HEAD URLs listed in the signed policy's `routine_egress_urls` continue
without a prompt. Query strings and fragments cannot appear in that routine list.
Do not list state-changing endpoints as routine; HTTP method alone cannot prove
that a remote server treats a request as read-only. Credentials are always gated.

Approval binds the operation, target, method or secret-grant digest, host-issued
actor/domain/context, session, capability grants, provenance, and signed policy
digest. It expires within ten minutes and is consumed transactionally before the
broker call. An exception leaves the request consumed with an uncertain outcome.
Neither automatic retries nor a restart restore it to pending.

Sandboxed computation remains read-only and network-isolated. There is no new
publisher, email sender, protected deletion, security configuration writer, or
writable-workspace promotion adapter. Those operations remain unsupported. The
schema reserves operation names for future reviewed adapters; listing a name
is not an implemented executor. Existing policy ESCALATE/DENY decisions still
stop; this feature does not automatically resolve them.

All untrusted operations must reach the trusted dispatcher. Never expose broker
sockets, host methods, signing keys, policy keys, or the approval state directory
to the workload. Calling a broker directly from trusted host code is outside
this mediation contract. Application integration coverage must be reviewed.

## Trust and physical presence

The verifier accepts only enrolled OpenSSH `ecdsa-sk` or `ed25519-sk` public keys
with application `ssh:bull-approval`. It requires both signed user-presence and
user-verification flags, verifies the exact message with OpenSSH, and uses a
separate signature namespace. Plain text, Enter, and ordinary software SSH key
types are not approval credentials.

Security-key encoding does not prove a manufacturer's hardware was used. Enroll
keys under operator supervision on a real supported authenticator. Synthetic
software SK fixtures are used in CI to validate the wire protocol; they are NOT
physical-human evidence. Enrollment attestation validation is not implemented.
A touch/PIN also does not prove informed consent. The signing interface trusts
the operator computer's display; a separate trusted action display is not supplied.
A compromised host administrator, operating system, trusted process, or enrolled
credential authority is outside this boundary. Do not advertise immunity to them.

OpenSSH references: [ssh-keygen](https://man.openbsd.org/ssh-keygen),
[signature format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig),
[security-key format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f).

## Operator setup

On the trusted operator machine, enroll a dedicated authenticator credential:

```sh
ssh-keygen -t ecdsa-sk -O application=ssh:bull-approval -O verify-required -f /PRIVATE/approval-key
```

Replace `/PRIVATE` with an existing owner-only directory. Do not place the key
handle, enrollment evidence or configuration in Git or an agent workspace.
Provision a separate mode-0700 directory owned by the BULL service UID for
approval state. Place only the public key (first two fields of the `.pub` file)
in the signed deployment policy configuration:

```json
{
  "state_directory": "/PRIVATE/bull-approvals",
  "credentials": {"operator-id": "sk-ecdsa-sha2-nistp256@openssh.com REPLACE_WITH_ENROLLED_PUBLIC_KEY"},
  "routine_egress_urls": [],
  "ttl_seconds": 300
}
```

The placeholder is deliberately invalid; there is no sample production credential.
Use `bull policy --approval-config /PRIVATE/approval-config.json --output ...`
with the usual explicit capability list and deployment signing key. Regenerate
and sign the integrity manifest after upgrading BULL. Existing profiles without
this configuration can still run contained workloads but protected broker calls
fail closed. Removing a credential and re-signing policy revokes future use and
invalidates pending requests bound to the previous policy. In-flight operations
past the final authorization check cannot be undone by revocation.

## Host integration and ceremony

The trusted application calls the existing production dispatcher. Catch
`ApprovalRequired` to display its `request_id`; do not retry in an automatic loop.
The public request is in `exception.request`. The trusted host can export it:

```sh
bull approval show REQUEST_ID --output /PRIVATE/request.json
bull approval sign --request /PRIVATE/request.json --key /PRIVATE/approval-key --output /PRIVATE/request.sig
```

Signing displays the frozen canonical request and invokes the authenticator.
It never executes the requested effect. Return the resulting signature through
the application's authenticated operator channel. The host resumes the original
broker operation using `ApprovalProof(request_id, credential_id, signature_bytes)`
in its `approval=` argument. A signature does not carry ambient authority:
changed requests, sessions, domains, grants and policies are rejected.

`bull approval cancel REQUEST_ID` cancels a pending request. There is no override,
reset-to-pending, password fallback or automated agent approval endpoint. CLI
commands use the signed deployment policy and existing authenticated audit config.
The host application supplies its own operator-channel authentication and UI;
this release does not ship a browser approval service.

The 10,000-record local database budget fails closed when exhausted. Archive only
expired, resolved state under operator control and rotate the deployment session;
never delete/recreate state to reuse a consumed request. Audit delivery failure
after consumption leaves a consumed request; reconcile audit and actual effect
before requesting a new action. This is at-most-once authorization, not a guarantee
of exactly-once remote effects or atomic remote transactions.

## Validation

`tests/test_human_approval.py` verifies real cryptographic signatures using
synthetic test credentials, request binding, cancellation, expiry, key replacement,
parallel consumption, restart and audit failures. Controlled broker fixtures
verify no callback occurs before valid approval and at most one afterward.
They do not certify real TLS peers, physical interaction or the Linux sandbox.

Run `PYTHONPATH=src python tools/hardware_approval_check.py --public-key ... --key ...
--output /PRIVATE/new-ceremony` on the enrolled operator device. It signs a fresh
harmless fixture, checks the signature and reuse rejection, and saves evidence.
It does not perform the real protected operation. Production deployment also
requires the existing host and real-KVM checks and a live operator-approved broker
operation reaching the deployment audit collector.
