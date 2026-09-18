# BULL hardening field manual

This commit adds three hardening primitives. This document says how to wire
them in. No system is impenetrable; the goal is that every layer an attacker
beats costs them detection surface and buys the audit trail time.

## 1. Kill the broker/proxy socket race (secret_broker.py, egress_proxy.py)

Replace this pattern in both files:

```python
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(str(self.socket_path))
os.chmod(self.socket_path, 0o600)   # TOCTOU window
server.listen(16)
```

with:

```python
from .socket_hardening import accept_authenticated, bind_private_unix_socket

server = bind_private_unix_socket(self.socket_path)
# and at accept time, replace server.accept() with:
conn = accept_authenticated(server)   # verifies SO_PEERCRED uid
```

`bind_private_unix_socket` clamps the umask during bind (node is born
0600), forces the parent directory to 0700, refuses pre-planted symlinks,
and `accept_authenticated` authenticates every peer by uid — closing the
hole even if the socket path later leaks through a shared mount.

## 2. Prove the containerizer actually isolates

- In the production gate, statically audit the launcher every run:

```python
from .container_hardening import audit_launcher_script

findings = audit_launcher_script(launcher_text)
if findings:
    raise ProductionGateError(findings)
```

- Inside the namespace, before executing the workload:

```python
from .container_hardening import assert_sandbox_invariants

assert_sandbox_invariants()  # shared mounts, no_new_privs, CapEff == 0
```

- Ensure `_namespace_launcher.sh` invokes unshare with
  `--mount --propagation private` and runs `mount --make-rprivate /` before
  any bind mount. Without this, sandbox mounts leak to the host table.

## 3. Agent detection (AgentSentinel)

```python
from .agent_sentinel import AgentSentinel

def alert(report):
    audit.record("agent_sentinel", verdict=report.verdict,
                 score=report.score, signals=report.signals)

sentinel = AgentSentinel(on_verdict=alert, agent_at=0.6)
dispatcher.register_input_hook(sentinel.record_input_event)  # cadence signal
report = sentinel.evaluate()
```

Notes:
- The verdict combines environment markers, process ancestry, input-burst
  cadence, and I/O tempo with a saturating weighted fusion; one weak signal
  alone cannot flip the verdict to `agent`.
- Treat `agent` as a policy input (deny, downgrade domains, require human
  co-signature), not as a security boundary. Isolation remains the boundary.

## 4. CI supply chain

Pin workflow actions to commit SHAs instead of tags
(`actions/checkout@<full-sha> # v4`) in `.github/workflows/pytest.yml` and
`formal.yml`, and enable Dependabot for `github-actions` so pins receive
update PRs. Triggers and token permissions are already correct
(`pull_request`/`push` only, `contents: read`).

## Test

```bash
python -m pytest tests/test_hardening_additions.py -q
```
