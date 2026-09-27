# BULL enterprise agent gateway: design and implementation plan

Date: 27 September 2026

Status: proposed implementation; no MCP gateway or managed agent launcher is delivered by this document.

Inspected production source: `9a358f7630c862cc253e51578c2aacdac1d334ef`

Source tree: `09ca832d1a1de7c5ebdd4876e081da427c5ef926`

## 1. The decision in plain language

Build a **BULL enterprise gateway that exposes an MCP server and launches agents in a protected workspace**. Local enforcement remains on each managed machine; an enterprise control service distributes organizational policy and collects appropriately scoped evidence.

MCP supplies the connection that different coding agents can understand. BULL supplies permission checks, containment, human approval and records of what happened. A launcher puts the agent and its child processes inside that boundary. Installing a connector into an unrestricted agent only governs calls made through the connector.

The intended experience is simple: choose a repository, choose Codex or Claude Code, review the allowed actions, and start. The agent can inspect and change a disposable project copy. BULL controls access to the real project and outside services. Human approval covers actions beyond the initial grant. A prompt, skill or preset can explain this workflow; it cannot establish the security boundary.

Start with Linux and the two local CLI clients. Support additional clients through tested profiles. A cloud-hosted agent or an unrestricted desktop application does not become contained merely by connecting to a local service.

The enterprise objective is human-controlled code and infrastructure: agents receive explicit, limited authority; their work cannot acquire access to another project or system by producing persuasive text, spawning a helper, changing a config file or reusing a credential. Sections 14–16 add organizational controls and release requirements. They are requirements to implement and verify, not a statement that all controls already work.

| Approach | What it can do | Decision |
|---|---|---|
| MCP server alone | Offer BULL-controlled tools to compatible agents | Useful connection mode; label its limited coverage |
| Transparent HTTP/TLS proxy alone | Restrict destinations for traffic that reaches it | Retain as a network control; it cannot bind every encrypted request to a human-approved action |
| BULL gateway, MCP interface and contained launcher | Combine tool compatibility with enforcement over the managed session | Recommended product |
| Instructions or a skill alone | Teach agents the preferred workflow | Optional convenience, with no authority to grant access |

## 2. What the supplied red-team results establish

The supplied report describes an executable design model: 14 probes, zero reported breaches of its hardened version, eight reported leaks in its naive version, and seven reruns after correcting broker authority. Those are **reported model results**. The underlying CSV and executable model were not attached for inspection in this turn. Reruns must not be counted as additional independent attacks.

Use the report as a source of regression cases. It does not measure the safety of the actual dispatcher, the MCP SDK, an installed coding client or the Linux/KVM boundary. Menu disclosure, parser crashes and unauthorized external effects also need distinct outcome categories.

The most useful testing rule is to observe the effect. A returned object or an error-shaped response is insufficient. For process cases, record whether anything ran and which exact executable and arguments ran. For network cases, use a controlled receiver. For files, inspect the resulting bytes outside the disposable workspace. For credentials, verify whether protected bytes crossed the boundary.

## 3. Fixes found in the current source

These findings were checked against the source tree above, which is also the tree of readability commit `a7bac497be041e71a1ab17b6e15c5e393dffd49f`.

### F1. Network router and dispatcher contracts disagree

[`ProductionEffectRouter`](../src/bulldog/production_router.py) sends `headers` and `body` to `ProductionDispatcher.fetch_egress`. The inherited method in [`dispatcher.py`](../src/bulldog/dispatcher.py) accepts `url`, `method`, `domain_id`, `request` and `approval`; it accepts neither extra parameter.

A signature-binding check reproduced `TypeError: got an unexpected keyword argument 'headers'`. This is an integration failure before the network effect, not evidence of an escape. The three existing router tests passed; their permissive `lambda **kw` doubles do not check this contract.

**Fix:** define an explicit GET/HEAD contract for the first gateway release. Reconcile the router with the supported dispatcher/broker interface. Reject unsupported headers and bodies explicitly; never discard a requested payload and report the altered request as successful. Add POST, credential injection and payload support only with corresponding policy, canonicalization, approval and broker changes.

### F2. Domain authority is not forwarded by the router

The router passes `request` but omits `domain_id` for both network and secret routes. Domain-enabled dispatcher methods require that argument. An internal `DispatchRequest` already has a `domain_id` field.

**Fix:** construct the request from the host-owned session, forward its domain identity, and reject inconsistent identities. Test missing, frozen, sibling and revoked domains. MCP arguments must never supply a trusted `DispatchRequest`, a grant, a UID or a domain selection.

### F3. Broker peer authentication needs an actual transport boundary

[`EgressBroker`](../src/bulldog/egress_proxy.py) checks kernel peer credentials on its Unix-socket handler. The dispatcher currently calls the broker object's `fetch()` directly. [`profiles.py`](../src/bulldog/profiles.py) checks configuration markers and socket-parent properties, but that direct call itself does not authenticate a socket peer.

This can be an intentional trusted in-process arrangement. It cannot serve as evidence that a newly connected MCP caller crossed a kernel-authenticated broker boundary.

**Fix:** for the local gateway deployment, separate the authority service and broker processes, use the existing `broker_fetch()` client as the starting point, and test the real socket path. Only the authority service may reach the broker; the agent and MCP frontend must not. Bind per-session/domain authority before the call. A UID allowlist alone does not distinguish two sessions using the same UID.

### F4. The model's ceiling interpretation needs correction

The current implementation requires network capability in the host-issued domain ceiling and an explicit policy ALLOW, as well as the domain's destination permission and the broker's allowlist. See `_authorize_domain_broker_action`, `fetch_egress` and [`SecurityDomainRegistry.assert_egress`](../src/bulldog/security_domain.py).

**Preserve those checks.** The useful separation is between permission to ask a broker for a specific network operation and permission to open sockets from guest code. A guest can have no direct network while its session is granted a narrow brokered fetch. If policy configuration cannot express this cleanly, introduce explicit execution and broker policy sections through a reviewed migration. Do not remove an existing ceiling check to make a positive test pass.

### F5. Existing coverage is narrower than an agent-wide gateway

[`GovernedProductionExecution`](../src/bulldog/lifecycle_bridge.py) covers one host-bound command. The router covers three named operations. The combined guest evidence covers its candidate probes; it does not demonstrate every agent effect entering the production dispatcher. The router's coverage output also lists network approval without showing the existing preauthorized GET/HEAD exception.

**Fix:** publish an operation-by-operation coverage manifest and test the assembled path. Extend lifecycle admission deliberately, avoiding two inconsistent permission systems. Expose the routine-egress exception accurately in coverage and UI. Keep unrelated adapters unavailable until they have their own route and tests.

## 4. Authority and process layout

```mermaid
flowchart TD
    H[Human control panel] -->|Grants and approvals| D[BULL authority service]
    A[Contained coding agent] --> M[Unprivileged MCP frontend]
    M -->|Private authenticated channel| D
    D --> P[Production dispatcher]
    P --> W[Disposable workspace execution]
    P --> B[Scoped service brokers]
    B --> S[Approved outside services]
    D --> R[Protected audit and effect records]
```

The diagram shows the proposed action path. The launcher, agent configuration and OS controls must prevent shortcuts around it.

| Component | Authority it holds |
|---|---|
| Human control panel | Create/revoke grants; review exact changes; approve a bound consequential action |
| Agent, model output and project content | Request permitted operations; work within the assigned disposable environment |
| MCP frontend | Parse bounded protocol messages and relay requests; no policy keys or broker credentials |
| Authority service | Resolve trusted session/domain, registry, signed policy, lifecycle state and approvals |
| Production dispatcher | Apply production checks and admit a supported execution or broker effect |
| Service broker | Perform its narrowly defined external operation; hold service credentials outside agent memory |
| Launcher/setup helper | Establish isolation and session identity; privileged setup must be narrow and auditable |

Run the long-lived services without root wherever possible. Separate their OS identities from the untrusted agent. Keep configuration, keys, service binaries and audit state outside writable project paths. User namespaces alone do not establish a separate host identity; verify the actual mapping and file/socket access.

For local IPC, authenticate peers using kernel credentials and bind the connection to a launcher-created session. Prevent PID-reuse mistakes and cross-session reuse. A dedicated domain identity or a launcher-controlled inherited channel can establish that binding. A string in JSON, the MCP client name, and a protocol session identifier cannot establish it.

Grant changes take effect at dispatch, not just at connection time. Children receive subsets of parent rights and quotas. Concurrent sessions have separate workspaces, domains, approvals and effect keys.

## 5. Two operating modes with precise promises

**Connected tools mode:** an existing agent calls BULL through MCP. BULL controls those calls. Its UI says that the agent's other tools and connections remain outside this coverage.

**Managed session mode:** BULL launches the whole local agent process tree in a checked Linux environment. The agent sees a disposable workspace, narrowly selected configuration, and approved service channels. It cannot access the operator's home directory, SSH agent, cloud keys, Docker socket, arbitrary local IPC, host browser session or real project write path. Direct IPv4, IPv6, DNS, QUIC and proxy bypasses are tested.

Disable native external-effect tools in client profiles where supported. Enforce the boundary at the OS/service layer even if the client ignores its settings. Some clients require native execution inside their workspace; that can remain contained, but must be described as contained native execution, not as every subprocess being routed through `ProductionDispatcher`. A strict dispatcher-only profile must refuse clients that cannot meet it.

This is also why existing `bullgw` host filtering cannot stand in for action admission. Allowing a workload to contact an approved host freely would bypass per-action approval and journaling. In the managed profile, authorized brokers and a narrow inference adapter own external connections; transparent filtering supplies an additional network boundary.

A missing isolation feature produces a clear blocked startup. Do not silently substitute a weaker profile. Preserve the current offline image. Qualify namespace and KVM modes separately. macOS/Windows support needs its own Linux VM integration and evidence; a host-side connector is not equivalent.

## 6. The initial tools and their limits

Names below are proposed interfaces, not current commands.

| Proposed tool | Allowed behavior | Boundary |
|---|---|---|
| `repo.read`, `repo.search` | Read admitted files | No arbitrary host paths, symlink escape, hidden credential discovery or automatic resource dereference |
| `repo.status`, `repo.diff` | Inspect the session's project state | Bounded output; repository configuration and hooks cannot execute with host privilege |
| `workspace.apply_patch` | Edit the disposable workspace | Path confinement, byte limits, protected metadata and race-resistant resolution |
| `task.run` | Invoke a host-registered build/test profile | Exact derived argv; fixed executable identity and environment; test code remains untrusted |
| `net.fetch` | Scoped GET/HEAD through the broker | Network grant, destination/method policy, explicit ALLOW and required approval or routine grant |
| `change.propose` | Produce a reviewable patch and evidence | No direct push, deploy or change to host access controls |

Register each tool in a host-owned manifest: tool identity, schema digest, adapter, operation, argument derivation, resource policy, approval class and limits. `tools/list` reveals only tools available to that session. Every invocation rechecks authority even if the tool was previously listed.

Prefer rejecting unexpected authority fields over silently repairing a request. If a compatibility path deliberately strips fields, prove that attacker-controlled values never affect the authorized operation and tell the caller what happened. Never build shell commands by concatenating model text. A named test profile is still arbitrary execution of repository code, so it requires containment even when the argv is fixed.

Production currently favors admitted read-only execution. Useful coding needs a separately implemented writable disposable workspace and controlled export path. Do not unlock the host workspace to make editing work. Export approval binds the base revision and resulting patch; reject changed bases and strip special files, ownership changes and unsafe links. Tests and scans inform review but cannot certify generated code harmless.

Publishing, deployment, account changes, messages and secret use remain unavailable until typed adapters exist. Do not expose raw `secret.read` through MCP. Add narrowly defined credential use, with injection inside the broker and no secret in arguments, output or logs.

## 7. How the agent still reaches its model

A cloud-backed agent needs to send inference requests. Build a separate inference adapter for each qualified provider/client combination. It should limit API endpoints, operations, model selection, request/response size and spending; keep provider credentials in a trusted service. Do not give the agent an unrestricted HTTP CONNECT tunnel to a broadly useful provider domain.

The provider is an approved recipient of the data the agent sends. Network allowlisting cannot prevent disclosure through an already approved inference channel. Keep sensitive files out of the agent's readable workspace, show the chosen provider during setup, and disable remote tools/connectors that could introduce unmediated external effects. Qualify streaming, reconnects and cancellation, not just one completed request.

For a local model, expose only the selected inference endpoint through a narrow relay. Do not grant general access to localhost: other local services may hold powerful authority. Benchmark memory and latency on the operator's actual machine.

CLI subscription login, credential refresh and API-key mode may need different integration. Record which authentication mode was tested. Do not assume all account types can use the same relay or move a subscription credential into a new service without checking its supported use.

## 8. Protocol choices

Use standard MCP with a pinned, maintained SDK. Keep BULL's security logic behind the adapter so protocol changes cannot grant additional authority.

**Local first:** stdio between the client and a small frontend; authenticated private Unix IPC between that frontend and the authority service. Do not run the agent-launched frontend as root. Avoid an unauthenticated local TCP listener. Reserve stdout for protocol messages and use bounded, redacted diagnostics on stderr.

**Version support:** the official versioning documentation currently identifies `2026-07-28`, with per-request version metadata, while `2025-11-25` and earlier use initialization handshakes [1, 2]. Pin the actual SDK and qualified client versions. Implement only the versions they demonstrably support, and test each path. Protocol compatibility must never trigger a weaker authorization profile. Do not apply a blanket “must initialize first” rule to modern revisions, or accept modern request metadata as trusted identity.

**HTTP later:** for clients that need it, add Streamable HTTP with the applicable MCP authorization specification, audience/resource-bound tokens, OAuth authorization-code protection, Origin/Host validation and protected discovery. Use TLS for remote access. Keep downstream service credentials separate from client tokens. Protocol session identifiers are not authorization; token passthrough is forbidden [3–5]. This adds an attack surface and is not required for the first local CLI release.

Bound raw frame bytes before parsing, JSON nesting, tool arguments, response size, duration, concurrent calls and pending approvals. Reject ambiguous duplicate keys, invalid numbers, wrong types and unsupported methods. Follow the selected version's request, notification, error and cancellation semantics. Return a safe protocol error where permitted; never let malformed input create an effect.

Initially expose the small tool surface only. Additional MCP prompts, resources, apps, tasks or other extensions each need their own review. Treat tool descriptions, returned documents and annotations as untrusted content. Do not automatically approve or load downstream MCP servers discovered in project files [6].

## 9. Human approval, retries and stopping

Routine work should use bounded grants: project, actions, duration, destinations and budget. This keeps humans in control without asking them to approve every file read. The existing production routine GET/HEAD exception must remain explicit and narrowly configured; GET can itself have server-side effects and is not automatically harmless.

For consequential effects, reuse and extend the existing approval binding. Bind the canonical operation, parameters, target, actor/domain, policy digest, session, expiry and effect key. If payload support is added, bind exact payload bytes or their canonical digest, permitted headers and credential-use scope. Keep signing authority outside the agent. A client permission popup is not a substitute for BULL's proof.

The trusted approval UI must display the real destination and effect, escape untrusted text, and avoid instructions supplied by the tool result. Changes to policy, authority, approvals or the gateway's installation are never model-callable admin tools.

Keep MCP request IDs separate from durable effect keys. Extend [`effect_journal.py`](../src/bulldog/effect_journal.py) rather than inventing a competing journal. Consume authority before crossing the external boundary; preserve uncertain outcomes after timeouts or crashes. A lost response cannot authorize redispatch. Provider-supported idempotency and reconciliation are needed before claiming exactly-once external delivery.

A stop action revokes new admissions, invalidates pending authority and terminates the managed process tree where supported. Report already-sent or uncertain external effects; stopping cannot retract a delivered message or a completed remote request. Broker or audit failure must preserve the enforced policy, and logs must be protected from the workload.

## 10. The operator experience to build

The proposed commands below are a product specification. **They do not exist yet.**

```text
bull connect codex --project /path/to/repository
bull connect claude --project /path/to/repository
bull agent start codex --project /path/to/repository --mode managed
bull agent start claude --project /path/to/repository --mode managed
bull agent status
bull agent stop <session>
```

`connect` should inspect the installed client version, create a minimal host-owned profile, show the configuration changes, and test the connection. Preserve existing settings and provide removal. Repository-supplied settings cannot install services or widen grants. `agent start` should check the host, create a session/workspace, show the grant, launch the client, and verify protected operation before accepting work.

Codex and Claude Code document local stdio registration [7, 8]. These are the connection shapes to generate once a real frontend binary exists:

```text
codex mcp add bull -- /absolute/path/to/bull-mcp
claude mcp add --transport stdio bull -- /absolute/path/to/bull-mcp
```

Registration alone is not successful containment. Client permission/sandbox settings are additional controls [9, 10]. An unknown client version can use an explicitly labeled connected mode if compatible; it cannot receive a managed-session PASS without its qualification.

| Client family | Initial target | Evidence required before managed support |
|---|---|---|
| Codex CLI on Linux | First profile | Tool discovery, real task, blocked native bypasses, model connection, approval and revocation |
| Claude Code on Linux | Second profile | Same checks, including hooks, plugins and unsandboxed fallbacks |
| Other local MCP agents | Subsequent profiles | Client-specific tools, subprocesses, configuration and network behavior |
| Desktop/IDE agents | Later | Full process/service boundary; renderer and external helper paths included |
| Cloud-hosted agents | Connection-only initially | Remote execution containment requires a separate deployment |

The interface should state the actual mode, permitted project, active grants, running work, pending decisions and uncertain effects. A short human-readable receipt can say “changed three files in the temporary copy; no project export yet.” Evidence statuses must remain tied to the actual source, client, profile and environment.

## 11. Implementation sequence and exit gates

| Stage | Work and proposed files | Required result |
|---|---|---|
| 0. Repair contracts | Existing `production_router.py`, `dispatcher.py`, `profiles.py`, `egress_proxy.py`; `test_production_router.py`, production boundary and domain tests | Supported network call reaches its intended broker; domain and policy denial prevent effects; real IPC authentication tested |
| 1. Trusted tool registry | Proposed `agent_tool_registry.py`, `agent_session.py`; policy and lifecycle integration | Exact tool/argument/resource binding; no authority fields accepted from client; revoked sessions denied |
| 2. MCP frontend | Proposed `mcp_gateway.py`; optional pinned dependency; protocol/transport tests | Real serialized MCP calls traverse registry and production dispatcher; bounded parse and error paths work |
| 3. Contained launcher | Proposed `agent_launcher.py`, `client_profiles/`; existing production gates; narrowly scoped installation services | Whole agent tree contained; configuration immutable to workload; native bypass tests pass |
| 4. Useful coding workflow | Disposable workspace, patch/export adapter and inference adapters | Both clients complete an edit/test/review task without host-write, credential or direct-network escape |
| 5. Release qualification | Proposed `tools/qualify_agent_gateway.py`; console/evidence integration | Reproducible install and end-to-end results on eligible Linux hosts; failures and unsupported combinations visible |

Stage 0 precedes the server skeleton. Stages 1–2 can deliver a labeled tools-only preview. Managed-session support is gated on stages 3–5. Retain current offline and gateway candidate fixtures as separate evidence categories. The production-shaped VM must boot the actual assembled path, agent workload, service units and policy configuration before receiving a release qualification.

Update the integrity manifest and assurance registry for every newly trusted module. Do not solve missing production prerequisites by bypassing `ProductionRequirements`. A minimal setup needs to provision the actual signed-policy, audit and host controls, or state exactly why it is blocked.

## 12. Acceptance cases

These are proposed tests, not passing results. They extend the supplied probe classes and require positive controls so a gateway that denies everything cannot pass.

| ID | Attempt or scenario | Required observation |
|---|---|---|
| A01 | Tool outside session/deployment authority | No process, file or broker effect |
| A02 | `tools/list` under a restricted session | Only permitted, implemented tools; later revocation also enforced on call |
| A03 | Inject capability, UID, domain, argv or executable fields | Rejected by strict schema; any explicitly supported stripping path executes only the host-derived vector |
| A04 | Shell metacharacters, option injection, hostile environment or tool binary replacement | No unintended executable/arguments or inherited authority |
| A05 | Broker decision is SANDBOX, DENY, malformed or absent | Zero broker effects; legitimate contained process decisions tested separately |
| A06 | Missing, expired, replayed or cross-digest approval | No consequential effect; simultaneous replay admits at most one dispatch |
| A07 | Legitimate broker fetch with direct guest networking disabled | Controlled receiver sees exactly the authorized request |
| A08 | Host permitted by only one of domain/broker policy | No request to that host; operation capability is still required |
| A09 | Malformed/truncated/oversized JSON, duplicate keys or wrong types | Bounded protocol failure, live daemon and no effects |
| A10 | Unsupported version, legacy/modern mismatch, notification misuse | Protocol-correct bounded rejection; no authorization downgrade |
| A11 | Forged peer identity, direct broker connection or cross-session channel reuse | Real kernel/transport boundary denies access |
| A12 | Missing or frozen domain at router invocation | Denied before effect; valid host-bound domain succeeds |
| A13 | Schema changed after listing or approved tool swapped | Call binds registered identity/digest or fails |
| A14 | Agent invokes native shell, file tools, child agents or another MCP server | Host resources remain inaccessible; contained native behavior is recorded under its true coverage |
| A15 | Agent edits settings, hooks, service config, PATH or plugin definitions | Cannot widen permission or install host-executed content |
| A16 | Symlink/hardlink/path traversal and export race | No read/write outside admitted roots; approved patch cannot change after review |
| A17 | DNS rebinding, redirect, IP literal, metadata address or IPv4-mapped IPv6 | No forbidden destination; public destination control succeeds |
| A18 | Alternate IPv4/IPv6 port, raw DNS, QUIC, proxy env or local IPC | No direct escape; approved channels remain usable |
| A19 | Gateway down, service restart, policy revocation or agent kill | No new unauthorized effect; cleanup and uncertain state observable |
| A20 | Crash before dispatch, after remote acceptance or before receipt | Durable state distinguishes retryable work from uncertain effect; no blind resend |
| A21 | Model/provider connection and malicious prompt/tool response | Only granted data/effects accessible; no credential or approval authority exposed |
| A22 | Raw secret requested or printed through errors/audit | No protected bytes exposed to the agent or public report |
| A23 | Dependency installation or project test executes hostile code | Runs within containment and budgets; no host hooks or credential inheritance |
| A24 | Two agents contend, one forks children, or exhausted quota | No cross-domain authority/workspace access; aggregate limits hold |
| A25 | Positive coding task in each pinned client | Read, edit, test, human review and approved export all succeed |
| A26 | Missing host control, audit prerequisite or unsupported platform | Explicit blocked/unsupported result, with no weaker automatic launch |
| A27 | Future HTTP endpoint: hostile Origin, wrong audience, token reuse and SSRF discovery | Authentication and destination checks deny before dispatch |

For each applicable row, run a fast policy/contract test, a serialized transport test and an eligible-host integration test. Use real `ProductionDispatcher` paths for integration, not the development dispatcher or `**kwargs` mocks. Where doubles are needed in source tests, enforce actual signatures and label the boundary they replace.

Retain actual argv and effect observations in private fixtures, and publish redacted summaries. Include the source/image hashes, client and SDK versions, protocol revision, host controls, test fixture digest, requests, expected/observed effects and failures. Record blocked tests separately from failures and passes. Importing a supplied PASS summary cannot independently establish the observations behind it.

## 13. Hypotheses to test

| Hypothesis | Experiment | Evidence that would reject it |
|---|---|---|
| A small MCP adapter can reuse BULL without weakening authority | Run the same fixtures through the internal route and serialized MCP path | Different grants, arguments or effects for equivalent requests |
| Managed launch closes ordinary native-tool bypasses | Attempt direct host access and egress from each real client and its children | Any unapproved host/external effect |
| Broker access can coexist with an offline workload | Allow one scoped fetch and deny workload sockets in the same run | Allowed fetch fails, or workload gains general network access |
| Humans can supervise consequential effects without constant interruption | Run a fixed coding task set; measure completed tasks, approval prompts, time and errors | Safety depends on disabling controls, or routine tasks cannot complete |
| A shared gateway can support multiple client families | Pin Codex and Claude versions; repeat the same task and attack fixtures | Client-specific paths bypass policy or cannot be reliably contained |

Compare the naive and hardened models on the same workload, granted authority and effect oracle. Measure usability and performance as well as blocked attacks. Report medians and tail latency from recorded samples rather than inventing a speed claim. A repeated deterministic suite or zero successes in 14 probes cannot establish a general escape probability.

## 14. Enterprise control and deployment

Follow the resource-centered authorization approach described in NIST SP 800-207 [13]: device location and being on a company network do not themselves establish permission. BULL should authenticate the operator and machine, then check authority for the particular resource and action. This is an architectural alignment, not a certification.

### Organization identity and human authority

Integrate with an organization's existing identity provider through a supported OIDC or SAML integration. Map identities and groups to scoped roles; use SCIM or the provider's supported lifecycle integration for enrollment and removal. Do not build a new enterprise identity provider inside BULL. Bind machine identities independently from human sessions, rotate credentials, and use mutual TLS for authenticated fleet control traffic.

Separate operators, project owners, approvers, security policy administrators, release administrators and auditors. Roles may narrow grants according to project, environment, destination, operation and duration. Sensitive production changes can require two distinct human approvals, with a common action digest and no self-approval. A chat message, model decision, existing login cookie or MCP client label cannot confer those roles.

Store organizational policy as signed, versioned configuration with explicit expiry and monotonic revision checks. Device/project policies can narrow the organizational grant. An explicit organization-level exception requires the relevant human role and an auditable policy change; a local config cannot silently widen it. Enrollment and recovery are human-controlled operations outside the model's tool catalog.

### Deployment and fleet control

Keep the local gateway usable as a single-machine installation and add a self-hosted control service for teams. Distribute signed profiles to enrolled hosts and verify them locally. Inventory exact gateway, policy, kernel/guest image, SDK and client versions. Drift must be visible and block affected grants according to policy.

Never make the fleet service an unrestricted remote shell. Policy distribution, qualification requests, revocation and upgrade orchestration need separate authenticated APIs and scoped roles. Protect the control service as a high-value administrative boundary, with isolated signing keys, reviewable changes, backups and independent audit access.

Use an explicit offline lease if enterprise policy permits disconnected operation. It bounds rights, duration and budgets; expiration stops new admissions. Prompt revocation requires connectivity, so report disconnected machines honestly and test the maximum lease lifetime. Existing production audit requirements still apply: an offline lease cannot silently waive them.

For mutually untrusted tenants, use separate trust state, credentials, queues, storage and execution isolation. Include tenant identity in every authorization lookup, approval binding, job reference and audit query. Use dedicated worker/VM boundaries where the tenant threat model requires them. A shared UID or a database tenant column alone does not provide execution isolation.

### Data, services and contamination between projects

Keep source content local by default. Export metadata rather than raw prompts or repository contents to the control service unless organizational policy explicitly allows more. Set retention, region, access and deletion rules for artifacts and logs. Encrypt protected storage with managed, rotatable keys and test recovery after key rotation.

Treat model responses, retrieved documents, shared agent memory, skills, plugins and generated artifacts as untrusted material. Shared memory requires provenance and project/tenant access controls; importing a memory or skill cannot import authority. Quarantine generated packages and cross-project exports until the recipient's policy admits them. Scan for secrets and malware as an additional check, while retaining isolation and review even when a scan passes.

Give each external service a dedicated connector with resource scope, a named use, quotas and short-lived credentials where supported. For example, a repository-scoped review operation must not inherit organization administration rights. Git hosting, cloud deployment, ticketing, messaging and databases are separate adapter qualifications. Do not route an arbitrary downstream MCP server with its own unrestricted token around `ProductionDispatcher`.

### Hardware approval without a new cryptographic scheme

Build on the existing [`approval.py`](../src/bulldog/approval.py) and [`approval_crypto.py`](../src/bulldog/approval_crypto.py) security-key verification. Validate real enrollment, revocation and recovery. The existing [`hardware_approval_check.py`](../tools/hardware_approval_check.py) ceremony is a useful preliminary fixture, but it is not a complete gateway-to-external-effect test.

Qualify the full path: an actual client requests a harmless controlled effect, BULL displays the canonical action through a trusted interface, the enrolled device signs its bound approval, the production dispatcher consumes it, the controlled receiver confirms the exact effect, and replay fails. Record which physical authenticator and verifier were used.

Browser-based approval can later use a reviewed WebAuthn adapter [15], with challenge, origin, relying-party and user-verification checks. Do not equate any passkey with verified hardware provenance or an independent display of the transaction. Signature validity and user-presence flags do not prove that a human understood the action. The existing custom hardware provider requires its own device, firmware and protocol review before an enterprise hardware assurance claim.

### Availability, safe recovery and observability

Define the authority state as a consistency boundary. A redundant service must not approve the same consumed effect after failover. The existing local SQLite journal cannot simply be copied between active writers. Either keep one fenced authority writer per session or design and test a transactional shared store before horizontal scaling.

Preserve consumed approvals and uncertain effects across backups, recovery and upgrades. Reject rollback that could revive old permissions. Test clock changes, disk exhaustion, corrupt state, dropped acknowledgements and stale leaders. Fail closed for new consequential effects when required authority or audit state is unavailable; make the reason visible to the operator.

Export structured, redacted events to the organization's monitoring/SIEM system. Record attempted, denied, admitted, completed and uncertain operations distinctly. Protect audit retention from workload writes, verify chain/checkpoint continuity and alert on missing hosts, policy drift and repeated denials. Avoid putting secrets, full source files or sensitive model prompts into shared telemetry.

Emergency handling needs a tested organization-wide revoke/quarantine workflow, credential revocation, evidence preservation and a recovery runbook. Break-glass access is for authorized humans, time-limited and independently logged; it cannot be requested or approved by an agent. Document which already-issued external operations cannot be recalled.

## 15. Security-concern coverage map

Every row is a release obligation. “Source foundation” below means relevant code exists; it does not mark the enterprise path as qualified.

| ID and concern | Enforcement and acceptance evidence | Current boundary |
|---|---|---|
| E01. Agents acquire complete control | Narrow session grants, immutable host policy, no administrative tool, real native-bypass probes | Requires managed launcher and client qualification |
| E02. Prompt injection changes authority | Host-derived requests, approved tool registry, exact effect binding; hostile content cannot alter grants | Some source foundations; MCP/client path pending |
| E03. Secrets or private code escape | Read isolation, broker-held credentials, scoped inference/service routes, controlled exfiltration tests | Approved inference recipients can receive admitted data; content filters are additional controls |
| E04. One agent contaminates another project or tenant | Separate workspace/domain/state; controlled artifact promotion and shared-memory access | Enterprise isolation and cross-tenant tests pending |
| E05. Tools, adapters or brokers bypass dispatch | Explicit coverage manifest, real IPC, unknown adapters denied and effect-aware integration tests | Router contract defects identified; universal coverage not established |
| E06. A production image differs from the test fixture | Signed image manifest, pinned dependencies, reproducible recipe and client-to-service test in the installed image | Candidate tests remain candidate evidence |
| E07. A stolen or overpowered identity approves work | SSO lifecycle, least-privilege roles, device identity, optional dual control and revocation tests | Enterprise identity integration pending |
| E08. Hardware approval is forged or replayed | Real-device ceremony through the production path, action binding, expiry, replay and recovery tests | Signature verification exists; full gateway ceremony pending |
| E09. Crash/retry duplicates an external effect | Durable consumed keys, uncertain state, provider idempotency and reconciliation tests | Journal foundation exists; no blanket exactly-once guarantee |
| E10. Long autonomous runs exhaust or outlive authority | Time/budget leases, cgroups, disk/process limits, child quotas and repeated revocation/fault tests | Multi-day managed-client evidence pending |
| E11. Supply chain replaces the trusted code | Protected review/build, dependency locks, SBOM, signed artifacts/provenance, deployment verification and downgrade tests | Extend present source controls to every gateway artifact |
| E12. Evidence can be forged, lost or overclaimed | Protected local records, independent audit destination, exact version binding, private raw observations and redacted exports | Existing audit foundations; enterprise delivery/retention pending |
| E13. Control-plane outage opens access | Expiring signed leases, fenced state writers and tested fail-closed behavior | Fleet failover/offline behavior pending |
| E14. Formal models imply more assurance than exists | State/transition mappings and implementation trace checks; model and implementation mutation tests | Design models and a mapping file exist; no formal equivalence established |
| E15. Only the author has attacked the system | Independent review of source, installed deployment and client bypasses; fixes verified by reviewer | External review remains external work |
| E16. “Zero breaches” is treated as a universal probability | Defined trial population, unique cases, blocked-run accounting, independent sampling where justified | The supplied 14 model probes cannot quantify general escape risk |
| E17. A malicious administrator, kernel or hypervisor defeats local enforcement | Minimize host privilege, patch/verify hosts, isolate trust roots, constrain remote credentials and detect drift | These remain trust boundaries; local software cannot guarantee safety against its compromised enforcement substrate |

Memory, message sending, persistent services, replication and cross-project sharing are explicit effects when supported, with adapters and grants. Leaving them absent from the initial catalog must not leave a native route available in a managed session.

## 16. Enterprise release gates

The enterprise release adds these gates to stages 0–5. Test infrastructure must report **blocked** when it lacks hardware, identity-provider access or required host features. It must never fabricate a passing fallback.

| Gate | Concrete deliverable | Pass condition |
|---|---|---|
| G1. Human and device identity | Enrollment, scoped roles, signed policy distribution and offboarding | Removed identity, stale policy, unauthorized device and self-approval cannot admit effects |
| G2. Tenant and project separation | Two organizations, multiple projects and concurrent hostile sessions | No cross-boundary credential, artifact, memory, queue or audit access |
| G3. Physical approval | Harmless real service fixture and an enrolled hardware device | Exact approved effect completes once; changed, expired, replayed and revoked proof fails |
| G4. Persistence and recovery | Controlled crash, network-partition, rollback, disk-full and failover campaign | No revived grants or automatic duplicate uncertain effects; recovery preserves audit/effect state |
| G5. Soak | A proposed seven-day pilot, then a longer customer-representative campaign | Recorded resource bounds, lease renewal/revocation, restart recovery and no observed unauthorized effects; duration alone is insufficient |
| G6. Artifact supply chain | Signed packages/images, SBOM, build provenance and verifier | Altered artifact, wrong origin, invalid signer and disallowed downgrade fail before launch |
| G7. Model-to-code traceability | Extend `formal/refinement-map.json` and trace fixtures for admitted effects | Mapped transitions checked against implementation traces; injected violations detected; claim remains bounded to checked traces |
| G8. Outside security review | Review package and a written independent assessment | Critical/high findings remediated and retested before general enterprise release; lower findings tracked with an accountable owner |
| G9. Operational readiness | Monitoring, incident/recovery runbooks, retention and restore drills | Measured alerting, revocation and recovery behavior meets declared targets on the supported deployment |

Use SLSA provenance as a reference for verifiable source/build/artifact relationships [14]. Claim a specific level only after assessing its actual requirements. Similarly, this plan does not confer SOC 2, ISO 27001, FIPS validation or any other certification.

Measure availability, revocation delay, approval latency, throughput and recovery time during qualification before setting customer-facing service commitments. Keep a support matrix for approved client versions and environments. A client or dependency update triggers focused regression and a staged rollout; it cannot inherit prior evidence solely because its product name is unchanged.

The first enterprise pilot should be deliberately narrow: two qualified local clients, one Linux deployment profile, isolated project editing, controlled fetch, reviewed export and a small number of approved service connectors. Enterprise scope expands when each adapter and deployment passes its gate.

## 17. Verification performed for this plan

Inspected the production source, authority paths, broker implementation, lifecycle bridge, code guide and existing tests. Reproduced the network signature mismatch using Python's `inspect.signature(...).bind(...)` without making a network request. Ran `tests/test_production_router.py`: **3 passed**. This demonstrates the current test blind spot; it is not gateway qualification.

No real Codex/Claude session, new MCP server, new kernel isolation run or new KVM qualification was performed for this plan. Runtime code is unchanged. The next engineering deliverable is stage 0 with effect-aware regressions, followed by the small stdio frontend and an explicitly scoped connection preview.

## References

Official documentation was consulted on 27 September 2026. Client and protocol support must be rechecked against the versions selected for implementation.

1. Model Context Protocol. [Versioning, current revision](https://modelcontextprotocol.io/docs/2026-07-28/learn/versioning).
2. Model Context Protocol. [Versioning and compatibility, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning).
3. Model Context Protocol. [Transports, 2025-11-25 compatibility revision](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
4. Model Context Protocol. [Authorization, 2025-11-25 compatibility revision](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).
5. Model Context Protocol. [Security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
6. Model Context Protocol. [Tools and security considerations, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
7. OpenAI. [Codex MCP connections](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
8. Anthropic. [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp).
9. OpenAI. [Agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security).
10. Anthropic. [Configure the sandboxed Bash tool](https://code.claude.com/docs/en/sandboxing).
11. BULL. [Production security boundary](PRODUCTION_SECURITY.md), [code reading guide](CODE_READING_GUIDE.md), [production assurance](HUMAN_FIRST_PRODUCTION_ASSURANCE.md) and [October review](OCTOBER_REVIEW.md), source revision stated above.
12. User-supplied executable-model red-team narrative, this conversation. Model source and CSV were not independently inspected.
13. NIST. [SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final).
14. SLSA. [Version 1.2: Provenance](https://slsa.dev/spec/v1.2/provenance).
15. W3C. [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/).
