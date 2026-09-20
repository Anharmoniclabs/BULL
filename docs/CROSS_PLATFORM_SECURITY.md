# Cross-platform security architecture

BULL uses one policy vocabulary but native kernel enforcement. A strict policy
is never represented by a plain subprocess on an unsupported host.

## Status

| Host | Strict backend | Current state |
|---|---|---|
| Linux | namespaces, chroot, no_new_privs, seccomp, Landlock, cgroups | Implemented; strict execution attests controls at runtime |
| macOS | Seatbelt plus parent resource/process supervision | Contract reserved; **fails closed until native implementation exists** |
| Windows | AppContainer/LPAC, restricted token, SID ACLs, Job Objects, mitigations | Contract reserved; **fails closed until native implementation exists** |
| Other | None | Fails closed |

## Non-negotiable rule

Portable API does not mean portable enforcement. ``select_backend()`` chooses
the host-native backend, and ``require_strict()`` raises unless it can prove
that required controls are installed. Callers must not replace that failure
with an unrestricted subprocess fallback.

## Policy model

```python
from bulldog.sandbox_backends import SandboxPolicy, strict_backend_attestation

policy = SandboxPolicy(
    workspace_writable=False,
    network_mode="none",
    max_output_bytes=1 << 20,
)
attestation = strict_backend_attestation()
```

A generic policy never grants raw secrets. Secret access remains mediated by
BULL's authenticated broker and security-domain authorization.

## macOS delivery requirements

A macOS strict backend must include:

- A deny-by-default Seatbelt profile produced by a verified native helper.
- Read-only runtime grants; scoped workspace and per-run temp grants.
- Network denial or an authenticated broker-only route.
- Sanitized inherited environment, including ``DYLD_*`` and agent sockets.
- Parent-enforced output, time, and process-tree budgets.
- Startup self-tests proving both allow and deny behavior.

## Windows delivery requirements

A Windows strict backend must include:

- Per-run AppContainer/LPAC and restricted token.
- Explicit AppContainer SID ACLs for runtime, workspace, and temp paths only.
- A Job Object with kill-on-close, process-count, memory, and CPU limits.
- Process mitigation policies and a sanitized inherited handle/environment set.
- No network capability unless an authenticated broker is enabled.
- Startup self-tests and an attestation naming the applied controls.

## Attestation discipline

Attestations report what was installed, not what was requested. Linux run-time
attestation currently verifies strict seccomp, Landlock, no_new_privs, PID and
network namespaces, the trusted runtime mount, and nonce binding. macOS and
Windows must provide equivalent concrete evidence before their backends return
``strict=True``.
