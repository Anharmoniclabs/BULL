# Local-model agent, sustained operation, and recovery

`tools/governed_agent.py` is a bounded autonomous agent wired to **ProductionRuntime
and ProductionDispatcher**. It asks an already pulled local Ollama model to select
one of two tools, feeds the result back, and continues until its step or time budget
is reached. The tools inspect a fixture and compute its SHA-256. Both execute in
BULL's strict sandbox after signed-policy checks, immutable snapshot admission,
ClamAV scanning, and authenticated audit anchoring.

The execution backend is the **host Linux NamespaceSandbox**, not the MicroVM.
The supervisor does not launch QEMU or dispatch through the guest runner. Separate
KVM acceptance cases do not make these model-selected actions VM executions.
See the [historical evidence summary](evidence/governed-agent-20260922/README.md)
for source identities, measured outcomes, and collector distinctions.

This is a deliberately narrow working integration. It does not establish complete
coverage of an arbitrary existing agent, general shell tools, successful credential
release, persistent VM sessions, unattended consequential actions, or multi-day
reliability. The trusted supervisor and local Ollama server run on the host; Ollama
is not itself sandboxed by this adapter. Model output cannot supply code, argv,
paths, endpoints, identities, capabilities, grants, or environment variables.
Trusted provenance describes the host's fixed tool implementation, not permission
for model-supplied commands. The exact model response is validated as untrusted JSON.

## Prerequisites

Use a reviewed checkout and Python 3.11+. Install it and its test dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
```

The host needs BULL's production Linux namespace/seccomp/Landlock support,
ClamAV with authentic databases, a writable delegated cgroup v2 subtree with
`cpu memory pids` enabled, and your own authenticated HTTPS collector. See
[deployment preparation](REPRODUCIBLE_DEPLOYMENT.md). No check is replaced by a
mock or a development dispatcher in a live agent run. Missing prerequisites stop
execution. Install `clamscan` using your supported host package workflow and
verify its databases with `sigtool --info`; do not substitute a success-returning
scanner stub.

Have Ollama listening on `127.0.0.1:11434`, with `qwen2.5:1.5b-instruct` already
pulled. Select another locally pulled completion model with `--model`. Remote/cloud
aliases, redirects, inherited HTTP proxies, and oversized responses are refused.
No model is downloaded automatically. Requests have a 60-second timeout and at
most three attempts; failed proposals never advance the durable step count.

### Optional user-systemd delegation

If your existing delegated subtree is reachable from this shell, use it. Otherwise,
on a host that supports user-service delegation, create a dedicated temporary
service. This touches only the new service and its worker processes:

```bash
BULL_AGENT_UNIT="bull-agent-lab-$(date +%s)"
systemd-run --user --unit="$BULL_AGENT_UNIT" \
  --property=Delegate=yes --property=DelegateSubgroup=coordinator \
  /usr/bin/sleep 86400
BULL_AGENT_CGROUP="/sys/fs/cgroup$(systemctl --user show \
  "$BULL_AGENT_UNIT.service" --property=ControlGroup --value)"
printf '%s' '+cpu +memory +pids' > "$BULL_AGENT_CGROUP/cgroup.subtree_control"
```

Use `--enter-coordinator` below to move only the dedicated worker into that
subtree. The existing chat, desktop, model server, and unrelated services are not
moved or restarted. If delegation is unavailable, follow the administrator setup
in the deployment guide; do not remove resource enforcement.

## Prepare private authority

Choose a **new** state path outside the repository and fixture workspace. Supply
your collector endpoint and private collector key, using your own values:

```bash
BULL_AGENT_STATE="$HOME/.local/share/bull/agent-run-01"
.venv/bin/python tools/deployment_setup.py init \
  --state "$BULL_AGENT_STATE" \
  --project-root "$PWD/examples/governed-agent" \
  --cgroup-parent "$BULL_AGENT_CGROUP" \
  --collector-url "$BULL_AGENT_COLLECTOR_URL" \
  --existing-collector-key "$BULL_AGENT_COLLECTOR_KEY_FILE"
```

Initialization creates fresh policy/integrity authority and an audit session. It
never rotates another deployment. This adapter requires exactly the default
`fs.read.project, process.exec` ceiling. Leave the private directory unshared.

## Run the reproducible acceptance procedure

```bash
.venv/bin/python -m pytest -q --junitxml=/tmp/bull-agent-regression.xml
.venv/bin/python tools/check_agent_cgroup.py \
  --parent "$BULL_AGENT_CGROUP" --enter-coordinator
.venv/bin/python tools/check_governed_agent.py \
  --deployment "$BULL_AGENT_STATE" \
  --output "$HOME/bull-agent-evidence-01" \
  --model qwen2.5:1.5b-instruct \
  --steps 100 --interval 5 --max-seconds 7200 \
  --enter-coordinator
```

The checker launches dedicated worker processes in three phases:

1. Persist a model-selected plan to the externally anchored ledger, then exit the
   worker with code 75 before dispatch.
2. Recover that plan, execute its read-only tool, then exit with code 76 before
   recording the completed result.
3. Recover again and finish the requested additional steps. Each committed result
   includes output hashes, sandbox attestation, and malware-scan evidence. Finish
   by testing a denied request for an ephemeral fixture credential through the
   actual production secret broker, then revoke the grant and close the broker.

The fault modes exit their own CLI worker only. They do not kill a model server,
VM, arbitrary PID, or process group. These are process-exit tests at specific
transaction boundaries, not kernel crash/power-loss or mid-workload kill tests.

A PASS requires the expected exit codes, two recovery events, all requested
steps, both tools used, no pending plan, successful sandbox evidence, correct
fixture outputs, and a credential denial. A model that never chooses both tools
fails the acceptance criterion. The measured elapsed time is reported; an iteration
count alone must not be described as a day-long or production-lifetime test.
`--max-seconds` bounds when new steps start; a current model request, tool, audit
request, or final interval may complete beyond that boundary.

## Recovery rules

The verified BULL audit ledger is the durable checkpoint. Recovery restores the
last 32 behavioral history events per security context before dispatch. The
installation identity remains stable. Supervisor bytes, fixed tool table, model
digest, and fixture hash are pinned at the first start; changed identities require
a new deployment. The signed BULL runtime manifest is checked separately.

An incomplete read-only tool may run again after a worker exit; committed steps
are not repeated. This is **not exactly-once execution**. Do not add write tools,
payments, message delivery, or credential use to this replay strategy without
operation-specific idempotency and recovery design.

For a normal continuation before the final credential-denial test:

```bash
.venv/bin/python tools/governed_agent.py \
  --deployment "$BULL_AGENT_STATE" --steps 1000 --max-seconds 86400 \
  --interval 5 --enter-coordinator
```

Here `--steps` is the absolute completion target. The checker instead requests an
additional number of steps. The final credential probe records a real denial in
behavioral history: do not reset that history to make a subsequent operation pass.
Use a fresh deployment for an independent acceptance run.

Audit delivery failure is fail-closed. After restoring the same collector, an
operator may explicitly add `--reconcile` to the worker command; it uses BULL's
existing remote reconciliation routine. It never deletes, truncates, or fabricates
ledger records. Corrupt or ambiguous history must be investigated, not reset.
Automatic collector-outage reconciliation is not implemented by this adapter.

## Audit and share

The checker creates `report.json`, per-phase logs, `ledger.jsonl`,
`collector-receipt.json`, and `SHA256SUMS.json`. It verifies the retained collector
receipt against the deployment session key and the final ledger head before export. These contain no deployment keys or fixture credential values.
The private deployment directory is **not** the evidence bundle.

```bash
.venv/bin/python tools/audit_governed_agent.py \
  "$HOME/bull-agent-evidence-01/ledger.jsonl"
```

This independently rechecks the chain, plan/completion sequence, protection
claims, and fixture outputs. Obtain the final head hash from your trusted collector
and pass `--expected-head HASH` to pin the check to an independently retained value.
A local hash chain or a hash copied from the same report cannot by itself establish
independent anchoring or collector durability. Preserve the source commit, dirty
patch/new files, model digest, database hashes, Python/dependency versions, and
host setup alongside the bundle. Generation is not bit-for-bit deterministic
across model runtimes and hardware.

The fixture secret test demonstrates **denial**, not successful approved credential
use. The production approval gate still requires an enrolled security key for
consequential release. Hardware presence, successful release/use, real third-party
API integration, arbitrary agent coverage, and prolonged service operation remain
separate evidence gates.
