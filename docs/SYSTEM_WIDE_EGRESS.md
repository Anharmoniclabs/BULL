# Guest egress: gateway and network rules

Egress means traffic leaving a system. BULL's guest network boundary combines a
gateway that checks requests with firewall rules that route or block traffic.
It is designed for a dedicated guest, not for installing over a general-purpose
host's network configuration.

## What runs where

| Component | Job |
|---|---|
| `src/bulldog/egress_gateway.py` | Handle HTTP, TLS server names and DNS requests according to policy |
| `src/bulldog/run_egress_gateway.py` | Load policy and start the listeners |
| `deploy/egress_redirect.nft` | Redirect TCP ports 80/443 and UDP port 53 to the gateway; filter guest output |
| `deploy/bull-egress-gateway.service` | Run the gateway as `bullgw` under systemd |
| `deploy/install_egress_gateway.sh` | Install the configuration in a dedicated guest |

The gateway strips agent-supplied HTTP Authorization headers and checks the
supported HTTP policy fields. For TLS, it checks the server name in ClientHello
(SNI); it does not decrypt or inspect the request body. Method/path restrictions
cannot be established from opaque TLS, so hosts requiring those restrictions
are denied on that path. DNS queries outside the allowlist receive REFUSED.

## Read the firewall rules

The rules exempt output owned by `bullgw` so the gateway can contact upstream
services. Selected web and DNS traffic is redirected to its local listeners.
The filter permits those translated requests and loopback traffic, subject to
the explicit TCP DNS and UDP 443 drops. Other output is dropped.

The gateway identity is trusted: a process that obtains `bullgw` can bypass
these checks. The administrator can also change the rules. These controls do
not defend against a malicious guest administrator or a compromised kernel.

The filter stays installed when the gateway stops. Redirected connections then
have no gateway listener to serve them. The service requires the redirect unit
before starting; a process being active is not itself proof that filtering works.

## Configuration and credentials

The installer requires a dedicated guest and validates an operator-configured,
nonempty allowlist before changing network rules. The default supplied policy
denies all targets. The service reads root-owned installed configuration rather
than a writable checkout; the policy is readable by the `bullgw` group.

Credentialed operations use the existing identity-bound BULL broker.
`token_broker.py` is a separate in-memory prototype and is not loaded by this
transparent gateway service. `semantic_intent.py` supplies capability hints;
those hints are not authority to expand permissions.

## What has been tested

The operator-reported `e6df4de` combined candidate passed 13 checks in a disposable
KVM guest containing separate workload/gateway users, nftables and systemd.
See [the named checks and remaining work](HUMAN_FIRST_PRODUCTION_ASSURANCE.md).
The fixture used restricted QEMU networking. It is not a released production
image or an independent adversarial audit.

Source tests exercise gateway behavior, including local socket/TLS fixtures and
a DNS refusal. Run the relevant tests from the repository root after contributor
setup:

```sh
python -m pytest tests/test_egress_gateway.py tests/test_semantic_intent.py tests/test_token_broker.py
```

The installer checks nftables syntax with `nft -c`. Source tests and syntax checks
do not replace guest route, bypass, stop and restart probes. New source revisions
need their own deployment evidence before being described as live-validated.
