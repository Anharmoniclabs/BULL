# Deployment checks from Codespaces

For the actual VM boot and physical-key steps, use
[the copy-and-run Codespaces checklist](CODESPACES_VM_AND_KEY_CHECKS.md).

For a new installation, start with [reproducible deployment](REPRODUCIBLE_DEPLOYMENT.md).
It supplies checked-in host setup, independent keys and a public guest recipe.
Use `--deployment /YOUR/private/state` to load that installation explicitly;
inherited BULL credentials are ignored. The environment-variable workflow below
remains available for manually managed deployments.

With `.[test]` installed and the pinned TLA+ jar downloaded, run:

```sh
python tools/deployment_check.py \
  --tla-jar "$HOME/bull-tla2tools-v1.7.4.jar" \
  --output "$HOME/bull-deploy-$(date -u +%Y%m%dT%H%M%SZ)"
```

This runs in the current environment and reports PASS, FAIL or BLOCKED for each
check. Missing prerequisites produce a nonzero exit. Source validation, a live
strict sandbox probe, synthetic security-key protocol tests and real loopback
TLS run automatically. A provisioned environment also runs the existing signed
policy, integrity, audit and resource-delegation production gate.

The KVM probe opens `/dev/kvm`, verifies its API and creates/closes an empty VM
descriptor. That is readiness evidence only. Guest execution requires real KVM
and prepared assets; the runner does not substitute emulation or modify host or
Codespace security settings.

## External collector

Set Codespaces secrets `BULL_REMOTE_AUDIT_ANCHOR_URL` and
`BULL_REMOTE_AUDIT_ANCHOR_KEY` to your existing collector configuration. Alternatively
pass `--anchor-url` and `--anchor-key-file` with a private mode-0600 key file outside
Git. Exact key-file bytes, including newlines, must match the collector. Supplying
the configuration authorizes fresh checkpoint metadata to that endpoint. The
runner does not create or rotate production keys. Redirects and invalid TLS fail.

The host check saves a verified acknowledgement bound to a fresh session and
ledger head. With KVM assets, the guest suite uses the same external collector and
requires a receipt matching guest session, record count and completion head.
The external master remains host-side; the guest gets separate disposable relay
authority. A service acknowledgement is not independent storage-durability proof.

## KVM assets

Set `BULL_DEPLOYMENT_ASSETS` or pass `--assets` pointing to a JSON manifest outside
Git. The schema is:

```json
{
  "kernel": {"path": "/PRIVATE/bzImage", "sha256": "REPLACE_WITH_VERIFIED_SHA256"},
  "rootfs": {"path": "/PRIVATE/rootfs.ext4", "sha256": "REPLACE_WITH_VERIFIED_SHA256"},
  "firmware": {"path": "/PRIVATE/qboot.rom", "sha256": "REPLACE_WITH_VERIFIED_SHA256"}
}
```

Placeholders are intentionally invalid. Use reviewed build outputs and preserve
their provenance; matching a supplied hash alone does not establish origin.
The runner checks hashes and invokes all five cases: allowed, denied, timeout,
cancel and missing protection. Every case must match the current commit and
selected assets. Current runtime source is copied into the guest test image.
See [guest dependencies](../microvm/guest/DEPENDENCIES.md) for kernel, userspace
and real offline scanner requirements. Nothing downloads or fabricates VM assets.

## Physical approval and review

Set `BULL_APPROVAL_KEY` and `BULL_APPROVAL_PUBLIC_KEY`, or pass `--approval-key`
and `--approval-public-key`, to the enrolled OpenSSH SK key handle and public key.
The authenticator must be accessible to the signing process. The ceremony displays
a harmless request and requires device interaction. Browser access to Codespaces
alone does not establish authenticator access. Touch/PIN entry is not automated.

The ceremony validates signed presence/verification flags, exact signatures,
single-use state and audit integrity. Synthetic protocol tests remain separate.
Supervised enrollment and informed consent require human evidence; manufacturer
attestation verification and a trusted hardware display are not supplied.

`review-packet.json` identifies source/result evidence and the independent review
scope. The runner always reports `certified: false`; independent review cannot be
awarded by this program. Review reports before sharing. KVM output includes
private disposable runtime authority: do not share runtime directories or keys.
