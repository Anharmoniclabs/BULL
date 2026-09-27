# Test BULL separately with local Codex and Claude Code

These instructions are for the **Linux terminal clients**, running on the same
machine as BULL. They create separate test accounts and leave your normal client
settings alone. BULL exposes one harmless tool, `installation_check`, which runs
the installed `/usr/bin/true` with no arguments. No BULL cloud account or external
collector key is needed. Sign in to each model provider normally when its client
asks; do not copy your normal home directory or credentials into this setup.

The earlier `run_local_agent_gateway.py` check stopped its temporary authority.
Its `/tmp` socket and deleted agent account are not a persistent installation.

| Test | Client account | MCP name | Authority socket |
|---|---|---|---|
| Codex | `bull-codex` | `bull_codex` | `/run/bull-codex-test/agent.sock` |
| Claude Code | `bull-claude` | `bull_claude` | `/run/bull-claude-test/agent.sock` |

Both authorities run as the separate, non-root `bull-authority` account. Each
test gets its own signed registry, private audit, lease and project. The kernel
account identity is the boundary; choosing two MCP names alone does not separate
agents. The accounts get no sudo or Docker membership.

This is an attachment procedure, **not a recorded Codex/Claude test result**.
The commands and registry shape have been checked against the repository; the
interactive clients have not been run in the editing environment. Native client
tools remain outside BULL. Keep client permission prompts enabled.

## 1. Prepare the local Linux host

Use your normal human administrator terminal. You need Bash, Git, Python 3.11+
with pip/venv, OpenSSH, libseccomp, util-linux (`unshare` and `setpriv`), and
ClamAV with usable official signature databases. These are the existing
[host prerequisites](REPRODUCIBLE_DEPLOYMENT.md), not KVM requirements. Install
missing packages using your distribution's package manager. A Codespaces pass
does not establish that this local machine has the required protections.

The following first-time setup creates three locked-password accounts, installs
the tested BULL revision, and creates two private socket directories. It refuses
existing names or paths rather than taking ownership of another installation.
Run the whole block once. If it stops partway, inspect the reported failure;
do not delete existing accounts or state just to repeat it.

```bash
(
set -euo pipefail
test "$(id -u)" -ne 0

for account in bull-authority bull-codex bull-claude; do
  if getent passwd "$account" >/dev/null || getent group "$account" >/dev/null; then
    printf 'STOP: account or group already exists: %s\n' "$account"
    exit 1
  fi
done
for path in /opt/bull-attachment-8ae922c /var/lib/bull-attachment-authority \
  /home/bull-codex /home/bull-claude /run/bull-codex-test /run/bull-claude-test; do
  if [ -e "$path" ] || [ -L "$path" ]; then
    printf 'STOP: path already exists: %s\n' "$path"
    exit 1
  fi
done

sudo useradd --system --user-group --create-home \
  --home-dir /var/lib/bull-attachment-authority --shell /bin/false bull-authority
sudo useradd --user-group --create-home --home-dir /home/bull-codex \
  --shell /bin/bash bull-codex
sudo useradd --user-group --create-home --home-dir /home/bull-claude \
  --shell /bin/bash bull-claude
sudo usermod --append --groups bull-codex,bull-claude bull-authority
sudo chmod 0700 /var/lib/bull-attachment-authority /home/bull-codex /home/bull-claude
sudo install -d -m 0700 -o bull-authority -g bull-authority /opt/bull-attachment-8ae922c
sudo install -d -m 0710 -o bull-authority -g bull-codex /run/bull-codex-test
sudo install -d -m 0710 -o bull-authority -g bull-claude /run/bull-claude-test

sudo -H -u bull-authority /bin/bash <<'AUTHORITY'
set -euo pipefail
umask 022
cd /opt/bull-attachment-8ae922c
mkdir -m 0700 private
git clone --single-branch --branch feat/enterprise-agent-gateway-20260927 \
  https://github.com/Anharmoniclabs/BULL.git source
git -C source switch --detach 8ae922ce24a0aa2ab653697c57eaf965268279ff
/usr/bin/python3 -m venv --copies venv
venv/bin/python -m pip install -e './source[test,mcp]'
cd source
../venv/bin/python -B - <<'PY'
from pathlib import Path
from tools.run_codespace_agent_gateway import prepare_public_runtime
prepare_public_runtime(Path('/opt/bull-attachment-8ae922c'))
print('Public source and runtime prepared; private state remains private.')
PY
AUTHORITY

sudo /usr/bin/python3 -I -B /opt/bull-attachment-8ae922c/source/tools/host_setup.py \
  --user bull-authority
)
```

The authority belongs to the two socket groups so it can assign socket ownership.
Neither client belongs to the authority group or the other client's group.
`PROVISIONED_NOT_TESTED` is expected from host setup; service startup still has to
pass BULL's runtime checks. If host setup reports disabled parent controllers,
review that specific message before using its documented
`--enable-parent-controllers` option. Do not disable a runtime gate.

These `/run` directories disappear on reboot. After a reboot, recreate only
missing socket directories with the same owners and modes and provision the
cgroup again. A used lease needs a new reviewed session; restarting it does not
reset its call budget or uncertainty state.

## 2. Make each client available under its test account

Open a new terminal for Codex, enter its account, then check the installed client:

```bash
sudo -iu bull-codex /usr/bin/setpriv --no-new-privs /bin/bash -l
codex --version
```

For Claude Code, use a different terminal:

```bash
sudo -iu bull-claude /usr/bin/setpriv --no-new-privs /bin/bash -l
claude --version
```

If a command is missing, install it **as that test account** using the official
[Codex CLI instructions](https://learn.chatgpt.com/docs/cli) or
[Claude Code instructions](https://code.claude.com/docs/en/setup). An installation
inside your normal user's private home will not automatically be accessible.
Keep that home private. Record each client's version and finish its normal login
before creating the one-hour test lease below. Exit the client after login;
leave its test-account terminal open. Do not launch either client as
`bull-authority` or root, or export `BULL_*` authority variables into it.

## 3. Start one BULL authority for the selected test

In a **human administrator terminal**, set `BULL_TEST_CLIENT=codex` for the first
test. Later, repeat the block with `BULL_TEST_CLIENT=claude` for the separate
Claude test. The first test's service can remain in its terminal while the
second uses another terminal. Each service stays in the foreground.

This creates a fresh one-hour lease with a two-call budget. The second call is
reserved for checking revocation; a successful revocation must prevent its
admission. The command refuses an existing deployment or journal.

```bash
(
set -euo pipefail
BULL_TEST_CLIENT=codex
case "$BULL_TEST_CLIENT" in codex|claude) ;; *) exit 1 ;; esac

sudo -H -u bull-authority /opt/bull-attachment-8ae922c/venv/bin/python -I -B - \
  "$BULL_TEST_CLIENT" <<'PY'
import hashlib, json, os, pwd, secrets, sys, time
from pathlib import Path
source = Path('/opt/bull-attachment-8ae922c/source')
sys.path[:0] = [str(source), str(source / 'src')]
from tools.deployment_setup import initialize

client = sys.argv[1]
if client not in {'codex', 'claude'}:
    raise SystemExit('Choose codex or claude')
os.umask(0o077)
root = Path('/var/lib/bull-attachment-authority') / client
root.mkdir(mode=0o700, exist_ok=False)
project = root / 'project'
project.mkdir(mode=0o700)
(project / 'README.txt').write_text('Harmless BULL MCP attachment fixture.\n')
(root / 'lease').mkdir(mode=0o700)
binary = Path('/usr/bin/true').resolve(strict=True)
registry = {
    'format': 'bull-agent-gateway-v1',
    'tenant_id': 'local-attachment', 'project_id': client,
    'session_id': secrets.token_hex(16),
    'agent_uid': pwd.getpwnam('bull-' + client).pw_uid,
    'expires_at': int(time.time()) + 3600, 'max_calls': 2,
    'tools': [{
        'name': 'installation_check',
        'description': 'Run the fixed harmless installation check',
        'operation': 'process.execute', 'argv': [str(binary)],
        'executable_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'timeout': 5,
    }],
}
registry_path = root / 'registry.json'
registry_path.write_text(json.dumps(registry))
initialize(root / 'deployment', project, audit_mode='local',
           cgroup_parent=Path('/sys/fs/cgroup') / ('bull-' + str(os.geteuid())),
           capabilities=['fs.read.project', 'process.exec'],
           gateway_registry=registry_path)
print('Created separate local deployment:', client)
PY

sudo /usr/bin/python3 -I -B /opt/bull-attachment-8ae922c/source/tools/host_setup.py \
  --user bull-authority --run \
  /opt/bull-attachment-8ae922c/venv/bin/python -I -B \
  /opt/bull-attachment-8ae922c/source/tools/serve_agent_gateway.py \
  --deployment "/var/lib/bull-attachment-authority/$BULL_TEST_CLIENT/deployment" \
  --state "/var/lib/bull-attachment-authority/$BULL_TEST_CLIENT/lease" \
  --socket "/run/bull-$BULL_TEST_CLIENT-test/agent.sock" \
  --agent-gid "$(id -g "bull-$BULL_TEST_CLIENT")"
)
```

Wait for `LISTENING`. A `BLOCKED` result is not an attachment-ready service.
Do not put this authority launch command in either client's MCP settings.

## 4. Attach Codex

Run this in the **bull-codex terminal** from step 2, after its authority is
listening. The read-only connection check must report `"ok": true` before
registration. The CLI writes its own MCP configuration under this test account.

```bash
mkdir -p "$HOME/attachment-test"
cd "$HOME/attachment-test"
/opt/bull-attachment-8ae922c/venv/bin/bull gateway check \
  --socket /run/bull-codex-test/agent.sock --server-uid "$(id -u bull-authority)"
```

```bash
codex mcp add bull_codex -- /opt/bull-attachment-8ae922c/venv/bin/bull-mcp \
  --socket /run/bull-codex-test/agent.sock --server-uid "$(id -u bull-authority)"
codex mcp list
codex
```

In Codex, use `/mcp` to inspect the connection. Ask:

> Call `installation_check` from `bull_codex` exactly once with `{}`. Show the
> actual structured tool result, including call_id, status, executed, argv and
> returncode. If it fails, stop; do not retry or substitute a native shell call.

Inspect the actual tool event. Success requires `status: COMPLETED`,
`executed: true`, the canonical `/usr/bin/true` argv from the registry, and
`returncode: 0`. A model saying "it worked" is not execution evidence.

## 5. Attach Claude Code

Start its separate authority using step 3 with `BULL_TEST_CLIENT=claude`. In the
**bull-claude terminal**, check the connection and register it for this empty
project only:

```bash
mkdir -p "$HOME/attachment-test"
cd "$HOME/attachment-test"
/opt/bull-attachment-8ae922c/venv/bin/bull gateway check \
  --socket /run/bull-claude-test/agent.sock --server-uid "$(id -u bull-authority)"
```

After that reports `"ok": true`:

```bash
claude mcp add --transport stdio --scope local bull_claude -- \
  /opt/bull-attachment-8ae922c/venv/bin/bull-mcp \
  --socket /run/bull-claude-test/agent.sock --server-uid "$(id -u bull-authority)"
claude mcp list
claude
```

Use `/mcp` to inspect the connection. Give Claude the same request as Codex,
substituting `bull_claude` for `bull_codex`. Inspect the actual tool event using
the same success criteria. Keep the client versions and results separate.

## 6. Check revocation and retained audit

After the first successful call returns, revoke that client's lease from a
**human administrator terminal**. Set the client name to the one being tested:

```bash
BULL_TEST_CLIENT=codex
sudo -H -u bull-authority /opt/bull-attachment-8ae922c/venv/bin/bull gateway revoke \
  --state "/var/lib/bull-attachment-authority/$BULL_TEST_CLIENT/lease"
```

Ask the selected client to call `installation_check` once more. BULL should
refuse it. If the client hides the tool or declines to call it, record that
behavior; it is not evidence of a received-and-rejected MCP tool call. In either
case, the revoked lease must not admit another execution. Do not remove
`REVOKED` or clear the journal to make the test pass.

Stop that authority with Ctrl+C in its service terminal after all tool calls have
returned. Then check its private audit as the authority account:

```bash
BULL_TEST_CLIENT=codex
sudo -H -u bull-authority /opt/bull-attachment-8ae922c/venv/bin/python -I -B - \
  "$BULL_TEST_CLIENT" <<'PY'
import json, sys
from pathlib import Path
from bulldog.local_audit import LocalAuditLedger, private_key
client = sys.argv[1]
if client not in {'codex', 'claude'}:
    raise SystemExit('Choose codex or claude')
deployment = Path('/var/lib/bull-attachment-authority') / client / 'deployment'
ledger = LocalAuditLedger(deployment / 'audit/ledger.jsonl',
    anchor_path=deployment / 'audit/local-checkpoint.json',
    anchor_key=private_key(deployment / 'secrets/local-audit.key'))
verified = ledger.verify()
if not verified.valid:
    raise SystemExit('Local authenticated audit did not verify')
records = [json.loads(line) for line in ledger.path.read_text().splitlines()]
attempts = [r['data'] for r in records if r.get('event_type') == 'gateway_attempt']
results = [r['data'] for r in records if r.get('event_type') == 'gateway_result']
one = (len(attempts) == len(results) == 1 and
       results[0].get('executed') is True and
       attempts[0].get('call_id') == results[0].get('call_id'))
print(json.dumps({
    'client_label': client, 'local_audit_valid': verified.valid,
    'exactly_one_recorded_execution': one,
    'call_id': results[0].get('call_id') if len(results) == 1 else None,
    'result_digest': results[0].get('result_digest') if len(results) == 1 else None,
    'scope': 'Retained BULL audit; compare call_id with the actual client tool event',
}, indent=2))
if not one:
    raise SystemExit('Expected exactly one completed installation check')
PY
```

Match the printed `call_id` to the actual client tool event, not a model-written
summary. This check does not independently authenticate the model provider or
verify a copied client response digest. Preserve the actual tool event and its
version alongside the audit summary before reporting a client attachment pass.

## 7. Finish the test

Remove each test registration from its own account and exit the client and
test-account shell:

```bash
# In the bull-codex terminal:
codex mcp remove bull_codex
```

```bash
# In the bull-claude terminal, from ~/attachment-test:
claude mcp remove bull_claude
```

Accounts and private evidence are retained for review. The accounts' provider
login sessions, if created, remain in their private homes until you log out or
remove them using the provider's normal process. No daemon, scheduled task or
systemd unit is installed by this guide. Revocation blocks future admissions;
it is not a kill switch for an already running native client operation.

## What a completed test establishes

Record Codex and Claude separately: OS, BULL commit, client version, MCP listing,
actual successful tool event, revocation behavior, and matching verified local
audit. A connection/listing alone is not a successful execution test. These
tests establish that the selected client can use BULL's fixed tool on this host.
They do not establish whole-agent containment, arbitrary repository editing,
long-running reliability, hardware approval or enterprise qualification.

The authority setup pins `8ae922c`, the revision of the operator-reported local
qualification, rather than silently installing a different runtime. Its Python
dependencies still resolve from the declared package ranges; preserve the
installed versions when retaining evidence. This guide itself adds no new
security verdict and does not reuse the earlier Codespace result as a local
desktop test.

## References

- [BULL gateway implementation and scope](AGENT_GATEWAY.md)
- [Operator-reported local MCP qualification](evidence/agent-gateway-local-20260927/README.md)
- [Official Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp)
- [Official Codex CLI](https://learn.chatgpt.com/docs/cli)
- [Official Claude Code MCP configuration](https://code.claude.com/docs/en/mcp)
- [Official Claude Code installation](https://code.claude.com/docs/en/setup)
