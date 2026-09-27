# BULL standards and compliance crosswalk

**Assessment date:** 2026-09-24  
**Implementation baseline:** `71e9d9fe9570f7b61770b9d5cca247d8ad269d1e` (assurance implementation merged to `main`)  
**Project:** BULL — Blocking Unauthorized Logic Loopholes  
**Scope:** source-code, deployment-control, and release-pipeline mapping

> **Important:** This document is a project-authored technical crosswalk, not a
> certification, legal opinion, SOC report, conformity assessment, NIST
> authorization, FIPS validation, or independent security audit. A control can
> be implemented in BULL without the organization or deployed system satisfying
> every requirement of the framework that contains that control.

BULL is an experimental execution-governance runtime for AI agents. Its strongest
standards alignment is around least privilege, authorization before effects,
sandbox isolation, information-flow control, audit integrity, release integrity,
human approval for consequential broker operations, and bounded execution.

The repository does **not** currently justify claims such as "NIST compliant,"
"ISO 27001 certified," "SOC 2 compliant," "FIPS validated," "EU AI Act compliant,"
"NIS2 compliant," or "SLSA Level 1+".

## Status vocabulary

| Status | Meaning |
|---|---|
| **Implemented** | A directly relevant technical control exists in source and has repository test/evidence hooks. This does not mean an external framework is fully satisfied. |
| **Partial** | BULL implements part of the requirement or mitigates part of the risk, but important scope/evidence remains outside BULL or is missing. |
| **Gap** | The expected control/evidence is not currently implemented or published in the repository. |
| **External** | Compliance depends mainly on deployment, organizational process, independent assessment, legal classification, or a third party. |
| **Out of scope** | The framework item addresses a function BULL is not designed to provide. |

## Machine-enforced assurance layer

BULL now packages a machine-readable control registry at
`src/bulldog/data/assurance_controls.json` and evaluates it through
`src/bulldog/assurance.py`. The command `bull assurance status` separates:

- `IMPLEMENTED` — source/test controls exist, but this is not live deployment proof;
- `PASS / FAIL / BLOCKED` — deployment or release evidence with fail-closed semantics;
- `EXTERNAL` — organizational, legal, assessor, or validated-module obligations
  that BULL is not allowed to self-certify.

`bull assurance status --dynamic` invokes the existing live host-certification
path for seccomp, Landlock, `no_new_privs`, network isolation and PID-namespace
evidence. `--require-complete` returns non-zero when required in-scope evidence is
missing. Project-authored assurance reports always set `certified: false`.

The production gate remains the enforcement authority. The assurance layer emits
structured evidence from that boundary; it does not create a second permission
engine or convert framework mappings into execution policy.

## Executive crosswalk

| Framework / standard | BULL status | What the repository supports | What it does **not** prove |
|---|---|---|---|
| **NIST Cybersecurity Framework (CSF) 2.0** | **Partial** | Strong technical overlap with access authorization, least privilege, data/security boundaries, platform protection, resilience, and monitoring/evidence. | Organization-wide GOVERN/IDENTIFY/RESPOND/RECOVER outcomes, risk ownership, asset inventory, business continuity, incident program, or a CSF assessment. |
| **NIST SP 800-53 Rev. 5** | **Partial** | Direct technical overlap with AC-3, AC-4, AC-6, AU-2/AU-9/AU-12, CM-7, SC-7, SC-39, SI-3, SI-7 and related controls. | A selected baseline, SSP, control implementation statements for a real information system, 800-53A assessment, RMF authorization, or ATO. |
| **NIST AI RMF 1.0** | **Partial** | Technical evidence contributes to GOVERN/MAP/MEASURE/MANAGE activities: threat boundaries, tests, measured enforcement, approval, audit, and fail-closed operation. | Full lifecycle AI risk management, impact analysis, intended-purpose assessment, organizational governance, model accuracy/fairness/explainability, or independent evaluation. |
| **NIST SSDF SP 800-218 v1.1** and **SP 800-218A** | **Partial** | Security policy, protected development workflow, tests/red-team probes, release hashing, machine-readable assurance controls, a CycloneDX guest-SBOM release path, GitHub Artifact Attestation provenance/signing hooks, vulnerability reporting, and reproducibility documentation. | A complete all-artifact SBOM, hermetic/reproducible builds for every artifact, an executed signed guest release on this baseline, or a full SSDF practice assessment. |
| **OWASP Top 10 for LLM Applications 2025** | **Meaningful technical alignment** | Particularly strong mitigation at the execution boundary for Prompt Injection impact, Improper Output Handling in governed command paths, Excessive Agency, and Unbounded Consumption. | Prevention/detection of every prompt injection, truthfulness, RAG/vector security, all application sinks, or security of integrations that bypass `ProductionDispatcher`. |
| **MITRE ATLAS** | **Mitigation mapping** | BULL provides controls relevant to agent tool invocation, prompt-injection impact, credential/tool abuse, host escape/sandbox evasion, exfiltration through tools, supply-chain compromise, and denial/resource abuse. | ATLAS is an adversary-technique knowledge base, not a compliance certification; BULL does not claim coverage of every ATLAS technique. |
| **CIS Controls v8.1** | **Partial** | Technical overlap with secure configuration, access control, audit logging, malware defenses, and application software security. | Enterprise asset/account inventories, training, recovery, incident-response operations, or a CIS Controls assessment. |
| **SLSA v1.2** | **Provenance pipeline implemented; no claimed level** | The guest-release workflow is wired to generate signed SLSA build provenance for its release subjects and verify attestations before draft release creation. | The new path has not yet been exercised by an intentional guest release on this baseline; this document therefore does not claim Build L1 or higher, nor does it assess every SLSA requirement. |
| **Sigstore / GitHub Artifact Attestations** | **Implemented release path; live release evidence pending** | The guest-release workflow uses GitHub Artifact Attestations with OIDC-backed short-lived signing identity, preserves Sigstore bundles, and verifies attestations before release creation. | This is separate from BULL's deployment HMAC trust model, does not certify runtime behavior, and has not yet produced a release artifact on this implementation baseline. |
| **in-toto** | **Partial** | The guest-release provenance/SBOM attestation path uses signed DSSE/in-toto statements through GitHub Artifact Attestations. | BULL does not define a custom in-toto layout with authorized functionaries/link metadata for every supply-chain step. |
| **SBOM (CycloneDX / SPDX)** | **Partial** | The guest-release workflow generates and validates a CycloneDX 1.6 SBOM from Buildroot `legal-info/manifest.csv`, then attests it for the rootfs. | This does not yet provide a complete Python/application/development-tool SBOM or prove that a signed guest release has been executed on this baseline. |
| **ISO/IEC 27001:2022** | **External** | BULL can support technical controls inside an ISMS, especially access control, secure configuration, logging, development security, and supplier/software-integrity evidence. | ISO 27001 certifies an organization's ISMS, not a Git repository. No accredited certification is evidenced here. |
| **SOC 2** | **External** | BULL can contribute controls relevant to Security, Availability, Processing Integrity, and Confidentiality depending on deployment. | A SOC 2 report requires management assertions and an independent CPA examination of a service organization's system/controls. None is evidenced by this repository. |
| **FIPS 140-3** | **Not validated** | BULL uses cryptographic primitives and OpenSSH security-key formats; its paper also cites FIPS 199. | Algorithm use or a FIPS citation does not equal CMVP module validation. No BULL FIPS 140-3 certificate or validated operational environment is claimed. |
| **EU AI Act (Regulation (EU) 2024/1689)** | **Partial technical support; external legal applicability** | Audit logging, human-approval mechanisms, cybersecurity containment, technical documentation and test evidence can contribute to requirements such as Articles 12, 14 and 15 when BULL is part of a covered high-risk AI system. | Classification, provider/deployer obligations, Article 9 lifecycle risk management, data governance, quality management, conformity assessment, registration, post-market monitoring, and legal compliance as a whole. |
| **NIS2 (Directive (EU) 2022/2555)** | **Partial technical support; external entity compliance** | Access controls, secure-development evidence, vulnerability reporting path, cryptographic integrity, audit evidence, isolation, and supply-chain hardening can support Article 21 measures. | Entity scope, management accountability, incident-reporting obligations, business continuity, training, supplier governance, risk policy, and national transposition requirements. |

---

## 1. Actual BULL control inventory

The following mappings are based on controls present in the repository at the
source baseline above.

### 1.1 Authority, least privilege, and complete mediation

**Relevant source**

- `src/bulldog/models.py`
- `src/bulldog/policy.py`
- `src/bulldog/canonicalizer.py`
- `src/bulldog/dispatcher.py`
- `src/bulldog/profiles.py`
- `src/bulldog/security_domain.py`
- `src/bulldog/session_guard.py`
- `tests/test_full_argv_and_production_wiring.py`
- `tests/test_redteam_authorization_binding.py`
- `tests/test_security_domains.py`

**Implemented behavior**

- Explicit capabilities are represented separately from model text/provenance.
- Production execution goes through `ProductionDispatcher` /
  `ProductionRuntime`.
- OS execution requires `process.exec`.
- Production command authorization is bound to the exact host-authorized argv,
  rather than treating a generic capability as permission to execute arbitrary
  commands.
- Host-issued security domains constrain child authority; child capability
  ceilings cannot exceed parent authority.
- Model-supplied authority is not treated as trusted host authority.
- Serious domain violations can freeze a root domain.

**Framework overlap**

- NIST CSF 2.0: **PR.AA-05** (policy-defined, managed, enforced authorization;
  least privilege).
- NIST SP 800-53: **AC-3 Access Enforcement**, **AC-6 Least Privilege**, and
  portions of **AC-4 Information Flow Enforcement**.
- OWASP LLM06 Excessive Agency.
- CIS Control 6 Access Control Management.
- MITRE ATLAS agent-tool-abuse / unauthorized-tool-invocation attack paths.

**Limit**

These properties only protect effects that actually pass through the trusted
BULL integration boundary. `CapabilityDispatcher` exists for compatibility and
development. Integrations that bypass `ProductionDispatcher`, expose trusted
host methods directly, or give the workload broker sockets are outside the
production mediation claim.

### 1.2 Human approval for consequential broker operations

**Relevant source**

- `src/bulldog/approval.py`
- `src/bulldog/approval_crypto.py`
- `docs/HUMAN_APPROVAL.md`
- `tests/test_human_approval.py`

**Implemented behavior**

- Policy/domain authorization happens before approval.
- Approval binds the specific operation, target, context, session, grants,
  provenance and signed-policy digest.
- Requests expire and are transactionally consumed; they are not automatically
  replayed after uncertain outcomes.
- The verifier accepts enrolled OpenSSH security-key formats and requires
  user-presence and user-verification flags.
- Approval cannot override an existing DENY/ESCALATE result.

**Framework overlap**

- OWASP LLM06 human approval for higher-impact actions.
- NIST access-control and separation-of-duty concepts.
- NIST AI RMF MANAGE activities involving risk treatment and human intervention.
- EU AI Act Article 14 **supporting mechanism** for human oversight.

**Limit**

The repository explicitly states that CI uses synthetic security-key fixtures.
A real authenticator ceremony, trusted enrollment, deployment operator channel,
and end-to-end production evidence remain separate requirements. A touch/PIN
does not by itself establish informed consent, and the current host display is
trusted.

### 1.3 Linux containment and MicroVM isolation

**Relevant source**

- `src/bulldog/namespace_sandbox.py`
- `src/bulldog/_namespace_launcher.sh`
- `src/bulldog/seccomp_policy.py`
- `src/bulldog/landlock_policy.py`
- `src/bulldog/resource_limits.py`
- `src/bulldog/cgroup_scope.py`
- `src/bulldog/host_certify.py`
- `src/bulldog/microvm.py`
- `src/bulldog/guest_engine.py`
- `microvm/guest/init`
- `docs/PRODUCTION_SECURITY.md`
- `docs/MICROVM_RELEASE_STATUS.md`

**Implemented behavior**

- PID, mount, user, network and IPC namespace isolation on the supported Linux
  production path.
- `no_new_privs`.
- Strict production seccomp profile using default-deny/EPERM with an explicit
  userland syscall allowlist.
- Landlock filesystem restrictions.
- Cgroup v2 CPU/memory/process budgets plus process/resource/output limits.
- Nonce-bound backend attestation checked by the trusted parent before workload
  exec.
- Read-only trusted runtime mounted separately from untrusted workspace content.
- Optional QEMU/KVM MicroVM route with a separate guest kernel, read-only inputs,
  constrained devices, and no guest NIC in the documented one-shot path.

**Framework overlap**

- NIST SP 800-53 **CM-7 Least Functionality**, **SC-7 Boundary Protection**,
  **SC-39 Process Isolation**, and parts of **SI-7 Software, Firmware, and
  Information Integrity**.
- NIST CSF PR.PS / PR.IR technical protection and resilience outcomes.
- OWASP LLM01 Prompt Injection impact containment, LLM05 Improper Output
  Handling, LLM06 Excessive Agency, and LLM10 Unbounded Consumption.
- MITRE ATLAS Escape to Host / Virtualization or Sandbox Evasion mitigations.
- CIS Control 4 Secure Configuration and Control 16 Application Software
  Security.

**Limit**

Namespace isolation shares the host kernel. The MicroVM path adds a separate
guest kernel but still trusts the host/hypervisor. The project does not claim
protection from a malicious host administrator, a compromised kernel/hypervisor,
unknown allowed-syscall vulnerabilities, side channels, or behavior that stays
inside deliberately granted authority.

### 1.4 Filesystem admission and malicious-content controls

**Relevant source**

- `src/bulldog/filesystem_manifest.py`
- `src/bulldog/secure_fs.py`
- `src/bulldog/workspace_limits.py`
- `src/bulldog/snapshot.py`
- `src/bulldog/snapshot_worker.py`
- `src/bulldog/malware_scanner.py`

**Implemented behavior**

- Bounded project manifests.
- Secure path handling and project-root containment.
- Private snapshot construction.
- Validation before/after snapshot.
- Rejection of problematic symlink/hardlink/special-file conditions.
- Required malware scanning on the admitted execution copy in production paths.
- Hash binding after scanning to detect scan-to-execute drift.

**Framework overlap**

- NIST SP 800-53 **SI-3 Malicious Code Protection**, **SI-7 Integrity**, and
  input-validation concepts.
- OWASP LLM03 Supply Chain, LLM04 Data/Model Poisoning **only for admitted
  project content**, and LLM05 Improper Output Handling/path safety.
- CIS Control 10 Malware Defenses.

**Limit**

This is not a general proof that project data is semantically trustworthy, that
training data is unpoisoned, or that every malware family is detectable. It does
not provide model-weight provenance or dataset governance.

### 1.5 Secrets and outbound information flow

**Relevant source**

- `src/bulldog/secret_broker.py`
- `src/bulldog/egress_proxy.py`
- `src/bulldog/pinned_egress.py`
- `src/bulldog/socket_hardening.py`
- `src/bulldog/dispatcher.py`

**Implemented behavior**

- Credential access and network access are separate capabilities.
- Secret grants can be scoped by name, lifetime/use count and security domain.
- Broker operations require authorization before the broker is reached.
- Egress is constrained by host authority and broker policy.
- Address selection/pinning and TLS hostname verification are retained for HTTPS.
- Default MicroVM workload operation is networkless.

**Framework overlap**

- NIST SP 800-53 **AC-4 Information Flow Enforcement** and **SC-7 Boundary
  Protection**.
- OWASP LLM02 Sensitive Information Disclosure and LLM06 Excessive Agency.
- MITRE ATLAS tool-credential-harvesting and exfiltration-via-tool-invocation
  attack paths.

**Limit**

If an operator deliberately authorizes a secret to a caller, BULL cannot promise
that the caller will never observe or misuse that value. These controls reduce
ambient access and mediate outbound paths; they do not prove non-disclosure for
every authorized application flow.

### 1.6 Policy and runtime integrity

**Relevant source**

- `src/bulldog/policy_bundle.py`
- `src/bulldog/integrity.py`
- `src/bulldog/production_gate.py`
- `src/bulldog/host_certify.py`
- `tools/deployment_setup.py`

**Implemented behavior**

- Signed policy bundles.
- SHA-256 trusted-computing-base manifests.
- HMAC-SHA256 integrity-manifest authentication with deployment-owned keying
  material.
- Production gate verifies required configuration and dynamically certifies the
  actual sandbox backend.
- Production fails closed if required protections/evidence are missing.

**Framework overlap**

- NIST SP 800-53 **SI-7 Software, Firmware, and Information Integrity**.
- NIST CSF platform-security outcomes.
- CIS secure-configuration/application-security concepts.
- OWASP LLM03 Supply Chain.

**Limit**

BULL's HMAC mechanism is deployment-local integrity protection. It is not a
Sigstore identity signature, not an in-toto supply-chain attestation, and not a
FIPS 140-3 validation.

### 1.7 Audit integrity and external anchoring

**Relevant source**

- `src/bulldog/audit.py`
- `src/bulldog/audit_transport.py`
- `src/bulldog/anchor_service.py`
- `microvm/evidence.py`
- `deploy/cloudflare-audit/`

**Implemented behavior**

- Local hash-chained audit records.
- Authenticated remote checkpoints containing bounded metadata such as sequence,
  chain head, prior checkpoint and session identity.
- Authenticated acknowledgements bind the expected session/sequence/head.
- Failed checkpoint delivery prevents silent advancement and is handled
  fail-closed.
- The direct checkpoint mechanism does not transmit prompts, credentials, or
  full workload payloads.

**Framework overlap**

- NIST SP 800-53 **AU-2 Event Logging**, **AU-9 Protection of Audit
  Information**, **AU-12 Audit Record Generation**.
- NIST CSF DE.CM monitoring/evidence outcomes.
- CIS Control 8 Audit Log Management.
- EU AI Act Article 12 technical logging support.

**Limit**

A hash chain and HMAC prove integrity/authentication relative to trusted key and
state custody. They do not provide independent nonrepudiation against a malicious
administrator who controls every trusted copy/key. Retention periods, privacy
policy, enterprise log review, alerting, and incident response are deployment
responsibilities.

### 1.8 Verification, formal methods, and repository governance

**Relevant source**

- `.github/workflows/pytest.yml`
- `.github/workflows/formal.yml`
- `.github/workflows/guest-release.yml`
- `.github/dependabot.yml`
- `formal/tla/BullRuntime.tla`
- `formal/tla/BullSessionAudit.tla`
- `formal/tla/BullApproval.tla`
- `SECURITY.md`
- `docs/SECURITY_CLAIMS.md`
- `docs/REPRODUCIBLE_DEPLOYMENT.md`
- `microvm/governance/`

**Implemented repository controls**

- Security regression jobs on supported Python versions.
- Local-host adversarial probes and red-team tests.
- TLA+ parsing/model checking for three bounded design abstractions.
- Pinned GitHub Actions revisions in reviewed workflows.
- Hash verification of the pinned TLA+ tool.
- Guest build workflow records build/source materials and SHA-256 release hashes.
- Private vulnerability reporting is documented.
- Repository documentation records important test limitations and explicitly
  refuses to convert unavailable deployment inputs into passing evidence.
- Documented branch ruleset evidence requires pull requests, verified signatures,
  resolved conversations and required checks; it does not require a second
  approving reviewer.

**Framework overlap**

- NIST SSDF PO/PS/PW/RV practice families.
- NIST AI RMF MEASURE and GOVERN supporting evidence.
- OWASP LLM03 Supply Chain.
- CIS Control 16 Application Software Security.
- SLSA source/build hardening prerequisites.

**Limit**

Finite TLA+ models are design abstractions, not proofs of the Python interpreter,
kernel, QEMU, or every integration. A passing source workflow is not equivalent
to a current real-KVM deployment test or independent review.

---

## 2. OWASP Top 10 for LLM Applications 2025

OWASP is a risk taxonomy/guidance source, not a certification program.

| OWASP risk | BULL mapping | Status | Boundary |
|---|---|---|---|
| **LLM01 Prompt Injection** | Untrusted text/model output does not automatically become authority; capabilities, exact command binding, sandboxing, broker checks and approval constrain resulting effects. | **Implemented mitigation / not prevention** | BULL does not claim to detect every injection or make the model's reasoning trustworthy. |
| **LLM02 Sensitive Information Disclosure** | Secrets are brokered and scoped; egress is separately authorized; networkless execution is available. | **Partial** | Authorized secret access can still expose data to an authorized caller; application output channels remain relevant. |
| **LLM03 Supply Chain** | Pinned workflow actions, source/hash verification, integrity manifests, Dependabot, legal-info/source collection and controlled guest build inputs. | **Partial** | No machine-readable SBOM, SLSA provenance, Sigstore signing or in-toto chain. |
| **LLM04 Data and Model Poisoning** | Snapshot admission, malware scanning, integrity checks and read-only execution reduce risk from hostile project content. | **Partial / mostly out of scope** | No training-data quality system, model-training pipeline governance, or model-weight provenance service. |
| **LLM05 Improper Output Handling** | Canonicalization, exact argv authorization, secure path opens, sandbox execution and broker validation constrain dangerous model-generated tool arguments. | **Implemented for governed execution paths** | Does not sanitize unrelated application sinks such as HTML, SQL or templates that are outside BULL. |
| **LLM06 Excessive Agency** | Capability ceilings, policy-first dispatch, full-argv binding, scoped domains, approval gates and fail-closed brokers directly target excessive functionality/permission/autonomy. | **Implemented core control** | Depends on complete mediation through trusted BULL paths. |
| **LLM07 System Prompt Leakage** | BULL's security boundary does not rely on prompt secrecy; secrets can live outside prompts in a broker. | **Partial supporting control** | BULL does not itself guarantee system-prompt confidentiality. |
| **LLM08 Vector and Embedding Weaknesses** | No built-in vector database/RAG authorization layer. | **Out of scope** | A RAG application needs separate tenant isolation, access control and retrieval validation. |
| **LLM09 Misinformation** | Execution can be restricted despite wrong model output. | **Out of scope for truthfulness** | BULL does not verify factual correctness of model claims. |
| **LLM10 Unbounded Consumption** | cgroup v2, rlimits, process count, CPU/memory limits, file/workspace budgets, timeouts and bounded stdout/stderr. | **Partial** | Does not automatically enforce third-party model token/spend quotas or service-wide rate limits. |

---

## 3. NIST crosswalk

### 3.1 NIST CSF 2.0

The closest direct mapping is **PR.AA-05**: access permissions,
entitlements and authorizations are defined in policy, managed/enforced/reviewed,
and incorporate least privilege. BULL's capabilities, host-issued domains,
full-command binding and broker authorization are direct technical evidence for
the enforcement portion of that outcome.

At category level:

| CSF 2.0 area | BULL evidence | Status |
|---|---|---|
| **GV — Govern** | Security claims, threat/trust boundaries, vulnerability-reporting policy, release/evidence rules | **Partial** |
| **ID — Identify** | Explicit TCB/untrusted-component boundary and deployment prerequisites | **Partial** |
| **PR.AA — Identity Management, Authentication and Access Control** | Capability grants, security domains, human credential approval | **Implemented technical subset** |
| **PR.DS — Data Security** | Secret broker, egress controls, read-only inputs, integrity hashes | **Partial** |
| **PR.PS — Platform Security** | strict seccomp, Landlock, namespaces, signed manifests, MicroVM option | **Implemented technical subset** |
| **PR.IR — Technology Infrastructure Resilience** | fail-closed controls, resource budgets, cancellation/timeout cleanup | **Partial** |
| **DE.CM — Continuous Monitoring** | audit ledger/checkpoints and security event evidence | **Partial** |
| **RS / RC — Respond / Recover** | security reporting path and bounded checkpoint recovery semantics | **Gap/Partial at organization level** |

### 3.2 NIST SP 800-53 Rev. 5

This table maps **technical similarity**, not formal control satisfaction.

| Control | BULL evidence | Status |
|---|---|---|
| **AC-3 Access Enforcement** | Deterministic policy, production dispatcher, exact command/broker authorization | **Implemented technical mechanism** |
| **AC-4 Information Flow Enforcement** | Secret and egress brokers, network isolation, domain restrictions | **Partial** |
| **AC-6 Least Privilege** | Capability model and child capability ceilings | **Implemented technical mechanism** |
| **AU-2 Event Logging** | Structured local audit records | **Partial** |
| **AU-9 Protection of Audit Information** | Hash chain + authenticated checkpoint/acknowledgement | **Implemented technical mechanism** |
| **AU-12 Audit Record Generation** | Runtime/dispatcher/audit event generation | **Partial** |
| **CM-7 Least Functionality** | strict seccomp allowlist, minimal guest devices/no NIC, read-only mounts | **Implemented technical mechanism** |
| **SC-7 Boundary Protection** | network namespace, no guest NIC, mediated egress | **Partial** |
| **SC-39 Process Isolation** | Linux namespaces and optional separate MicroVM kernel | **Implemented technical mechanism** |
| **SI-3 Malicious Code Protection** | Required malware-scanning stage for admitted project snapshots | **Partial** |
| **SI-7 Software, Firmware, and Information Integrity** | signed policy/integrity manifests, hashes, verified build inputs | **Partial / strong overlap** |
| **SI-10 Information Input Validation** | canonicalization, bounded manifests, secure filesystem admission | **Partial** |

Missing evidence for a formal 800-53 program includes, among other things,
organization-defined parameter values, policy/procedure controls, personnel and
physical controls, a selected baseline, system security plan, assessment
procedures/results, POA&M, continuous-monitoring program and an authorization
decision.

### 3.3 NIST AI RMF 1.0

BULL is a **component** that can provide evidence to an AI risk-management
program; it is not itself a complete AI RMF implementation.

- **GOVERN:** explicit trust boundaries, security-claims discipline, repository
  governance and vulnerability reporting provide supporting evidence.
- **MAP:** the code distinguishes untrusted model/external content from trusted
  host authority and documents threat boundaries.
- **MEASURE:** regression tests, red-team cases, bounded TLA+ models, dynamic
  backend attestation and deployment evidence provide measurable observations.
- **MANAGE:** policy enforcement, fail-closed gates, resource isolation, approval,
  cancellation and domain freezing are concrete risk-response mechanisms.

Still required outside BULL: use-case/impact context, affected populations,
organizational risk appetite, model-performance and fairness metrics, governance
roles, monitoring of socio-technical harms, and lifecycle decisions.

### 3.4 NIST SSDF

The current final baseline is **SP 800-218 v1.1**. NIST published SP 800-218
Rev. 1 / SSDF v1.2 as an **Initial Public Draft** in December 2025; this document
does not treat the draft as a completed certification target. **SP 800-218A**
adds AI-specific secure-development practices and should be read with v1.1.

BULL has useful evidence across SSDF practice groups:

- **Prepare the Organization (PO):** security policy/claims, contribution
  expectations, release requirements and documented trust boundaries.
- **Protect the Software (PS):** protected source workflow, signed-commit
  requirements in the documented ruleset, integrity manifests, pinned workflow
  actions, SHA-256 release checks.
- **Produce Well-Secured Software (PW):** regression testing, adversarial probes,
  formal design checks, package installation smoke tests, guest build checks.
- **Respond to Vulnerabilities (RV):** `SECURITY.md` and GitHub private
  vulnerability reporting.

Key gaps remain: the CycloneDX/SLSA/Sigstore guest-release path still needs its
first intentional live release on this baseline; SBOM coverage is not complete
for Python/application/development tooling; parts of the build environment remain
non-hermetic; bit-for-bit guest-image reproducibility is not demonstrated; and no
independent security assessment requirement is enforced by repository rules.

---

## 4. MITRE ATLAS mapping

MITRE ATLAS is useful here as an adversary-behavior map. The following are
defensive correspondences, **not claims that every technique is defeated**.

| ATLAS-style attack path | Relevant BULL control |
|---|---|
| Prompt injection causing a tool action | Information is separated from authority; policy/capability/argv checks happen before effects. |
| AI agent tool invocation abuse | Production dispatcher mediates approved tool/command paths. |
| Tool credential harvesting | Secret broker, scoped grants, domain binding, protected broker sockets. |
| Exfiltration through agent tools | Separate network capabilities, egress broker policy, networkless sandbox/MicroVM path. |
| Escape to host / sandbox evasion | strict seccomp, Landlock, namespaces, `no_new_privs`, cgroups, optional KVM MicroVM. |
| Runtime-capability discovery | Exposed authority is intentionally constrained; this reduces impact but does not prevent reconnaissance. |
| AI/software supply-chain compromise | Signed BULL policy/integrity, pinned/hash-checked build inputs and actions; incomplete without SBOM/provenance/signing ecosystem. |
| Denial/resource abuse | CPU, memory, pids, timeouts, workspace and output budgets; not a complete service-level DoS solution. |

---

## 5. Software supply-chain maturity

### 5.1 SLSA v1.2

SLSA v1.2 is the current approved specification as of this assessment. Its Build
track requires provenance starting at Build L1.

**Current BULL conclusion: the provenance path is implemented, but no SLSA level is claimed.**

Positive prerequisites already present:

- source in Git;
- pull-request governance;
- pinned GitHub Action revisions;
- scripted builds;
- guest source pinning and hash checks;
- build records/source-material collection;
- SHA-256 release sums;
- explicit refusal to overwrite existing guest-release tags.

The guest-release workflow now creates SLSA build provenance through a pinned
GitHub Artifact Attestations action, preserves the generated Sigstore bundle, and
runs `gh attestation verify` before draft release creation. The provenance is
built from a deterministic checksum inventory of the release subjects.

What is still missing before making a level claim:

- an intentional guest-release run on this implementation baseline with retained
  release/attestation evidence;
- a control-by-control assessment against the normative SLSA v1.2 Build track;
- confirmation that the exact release workflow/builder satisfies the requirements
  of any level claimed, rather than inferring a level merely from the presence of
  provenance.

Higher levels require additional guarantees. BULL therefore continues to report
**no claimed SLSA level**.

### 5.2 Sigstore / GitHub Artifact Attestations

**Status: release pipeline implemented; first live release evidence pending.**

BULL's deployment HMAC-signed policy/integrity data remains a separate trust
model. The guest-release workflow now requests the GitHub OIDC/attestation
permissions, uses a pinned `actions/attest` revision, preserves the generated
Sigstore bundles, and cryptographically verifies the provenance and SBOM
attestations before it can create the draft release.

This is supply-chain evidence, not a statement that the resulting runtime is
safe or externally certified. The workflow has not been dispatched solely for
this documentation update, so there is no new signed guest release being claimed.

### 5.3 in-toto

**Status: Partial.**

The GitHub Artifact Attestation path emits signed DSSE attestations using in-toto
statement semantics for SLSA provenance/SBOM evidence. BULL still does not define
a custom in-toto layout describing authorized functionaries and signed link
metadata for every build/test/package step. Add such a layout only if the threat
model requires that extra step-level authorization model.

### 5.4 SBOM

**Status: Partial machine-readable SBOM coverage.**

`THIRD_PARTY_NOTICES.md` still correctly states that its short package inventory
is not an exhaustive dependency SBOM. In addition to that inventory, the
**guest-release workflow now generates CycloneDX 1.6 JSON/XML from Buildroot
`legal-info/manifest.csv`, validates the JSON, records the SBOM generator
resolved toolchain, and creates a signed SBOM attestation for the copied rootfs.**

Remaining gap: this is guest/rootfs coverage, not a complete Python package,
development environment, model, or deployment SBOM.

---

## 6. CIS Controls v8.1

BULL is not an enterprise CIS implementation, but its technical controls overlap
with several CIS control families:

| CIS Controls v8.1 family | BULL contribution | Status |
|---|---|---|
| **4 Secure Configuration of Enterprise Assets and Software** | strict production profiles, fail-closed prerequisites, read-only trusted roots, minimal MicroVM surface | **Partial** |
| **6 Access Control Management** | capability grants, domain ceilings, exact command authorization, credentialed approval | **Partial** |
| **8 Audit Log Management** | hash-chained audit, authenticated remote checkpoints | **Partial** |
| **10 Malware Defenses** | required scanner stage for admitted snapshots | **Partial** |
| **16 Application Software Security** | regression/red-team tests, formal invariants, security policy, vulnerability reporting | **Partial** |

Enterprise inventory, account lifecycle, security-awareness training, backup/
recovery operations, incident-response staffing and similar safeguards are not
provided by BULL.

---

## 7. ISO 27001, SOC 2, FIPS, EU AI Act and NIS2

### ISO/IEC 27001:2022

ISO/IEC 27001 specifies requirements for an organization's information security
management system (ISMS). BULL can be evidence for technical controls inside an
ISMS, but a repository cannot certify an organization.

**BULL status: no ISO 27001 certification claim.**

### SOC 2

SOC 2 is an examination/reporting framework for controls at a service
organization, performed by an independent CPA using the Trust Services Criteria.

BULL source code can contribute technical controls, but this repository does not
establish the design and operating effectiveness of a deployed service over an
audit period.

**BULL status: no SOC 2 report or SOC 2 compliance claim.**

### FIPS 140-3

FIPS 140-3 concerns validation of cryptographic modules through the NIST/CCCS
Cryptographic Module Validation Program (CMVP). NIST explicitly distinguishes
validated modules from products that merely implement approved algorithms.

BULL's use of SHA-256, HMAC, OpenSSH security-key algorithms, or a citation to
FIPS 199 does not make BULL FIPS 140-3 validated.

**BULL status: no FIPS 140-3 validation claim.**

If a deployment needs a FIPS requirement, the exact cryptographic module,
version, operational environment and validation certificate must be selected and
documented separately.

### EU AI Act

For a deployment that is legally classified as a covered **high-risk AI system**,
BULL may provide useful technical evidence toward:

- **Article 12 — Record-keeping:** automatic event/audit logging.
- **Article 14 — Human oversight:** credentialed approval can be one technical
  oversight mechanism for specifically integrated consequential actions.
- **Article 15 — Accuracy, robustness and cybersecurity:** isolation, capability
  enforcement, integrity checking, bounded execution and adversarial testing
  support the cybersecurity/robustness portion.

BULL alone does not satisfy those Articles in full and does not determine whether
a system is high-risk. It also does not provide the entire Article 9 risk
management system, Article 10 data governance, quality-management system,
conformity assessment, registration, instructions for use, or post-market
monitoring program.

**BULL status: technical support only; no EU AI Act conformity claim.**

### NIS2

NIS2 Article 21 requires covered essential/important entities to use appropriate
and proportionate technical, operational and organizational cybersecurity
risk-management measures. BULL can support parts of access control, secure
development, supply-chain hardening, vulnerability handling, cryptographic
integrity and logging.

It does not provide the entity's risk-analysis policy, incident handling
organization, business continuity/disaster recovery, cybersecurity training,
management accountability, statutory incident reporting, supplier governance,
or national-law implementation.

**BULL status: supporting technical control; no NIS2 entity-compliance claim.**

---

## 8. Highest-value gaps to close

These are evidence/control gaps, not prerequisites for experimenting with BULL.

1. **Run and retain the first intentional assured guest release.** Exercise the
   new CycloneDX + SLSA + Sigstore path on a reviewed release candidate, retain
   its release bundle/attestation verification, and record the exact source SHA.
2. **Extend SBOM coverage beyond the guest rootfs.** Add CycloneDX/SPDX coverage
   for the Python package and release/development dependencies without merging
   those distinct inventories into a misleading single component list.
3. **Harden the SBOM toolchain.** The top-level CycloneDX-Buildroot version is
   pinned and the resolved environment is recorded; add hashes/lock material for
   the generator dependency graph if practical for the release environment.
4. **Assess SLSA v1.2 requirements explicitly before claiming a level.** The
   provenance path exists, but the level must come from a normative requirement
   review plus retained release evidence, not from naming the technology.
5. **Add a custom in-toto layout only if the threat model needs functionary-level
   step authorization.** GitHub attestations already provide signed in-toto/SLSA
   statements; a separate layout should solve a defined security problem.
6. **Require independent security review for high-risk promotion.** Current
   documentation calls for it, but the repository's documented ruleset does not
   require a second approving reviewer.
7. **Keep code evidence and deployment evidence separate.** Every release should
   identify the exact source SHA, test environment, KVM/kernel/QEMU inputs,
   signed policy/integrity state, collector evidence and hardware-approval state.
8. **For FIPS-requiring deployments, select a validated module explicitly.**
   Record the CMVP certificate, exact module version and validated operating
   environment rather than relying on algorithm names.
9. **For ISO 27001 / SOC 2 / NIS2, build the organization-side program.** Add
   asset/risk inventories, incident response, continuity, personnel/training,
   supplier management, retention, access reviews and independent assessment
   evidence outside the runtime repository.
10. **For EU AI Act deployments, add a deployment compliance profile.** Record
    legal role and system classification, intended purpose, lifecycle risk
    management, data governance, log-retention responsibilities, human-oversight
    design, technical documentation, post-market monitoring and applicable
    conformity-assessment evidence.

---

## 9. Evidence caveats that must stay attached to any standards claim

- A passing unit/regression suite proves only the exercised cases.
- TLA+ checks are bounded design models, not kernel/runtime implementation proofs.
- Historical KVM/deployment results apply to the exact recorded source/assets,
  not automatically to later commits.
- The namespace sandbox trusts the host kernel.
- The MicroVM path trusts the host/hypervisor.
- Audit authentication trusts key custody and trusted state.
- Human approval trusts enrollment, operator channel/UI, the host and the
  credential authority.
- Malware scanning is not proof that admitted data is benign.
- Signed deployment policy/integrity manifests do not equal public supply-chain provenance; the guest-release attestation path is separate evidence and must be evaluated on its own exact release run.
- A project's `certification/` filenames or self-verification outputs are not
  third-party standards certification.
- Framework alignment must never be rewritten as external certification without
  the required assessor/authority evidence.

---

## 10. Official framework references

- NIST Cybersecurity Framework 2.0: <https://www.nist.gov/cyberframework>
- NIST SP 800-53 Rev. 5: <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
- NIST AI Risk Management Framework: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST SSDF SP 800-218 v1.1: <https://csrc.nist.gov/pubs/sp/800/218/final>
- NIST SP 800-218A (Generative AI / dual-use foundation model profile): <https://csrc.nist.gov/pubs/sp/800/218/a/final>
- OWASP Top 10 for LLM Applications: <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- MITRE ATLAS: <https://atlas.mitre.org/>
- SLSA v1.2: <https://slsa.dev/spec/v1.2/>
- Sigstore: <https://docs.sigstore.dev/>
- GitHub Artifact Attestations: <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds>
- in-toto: <https://in-toto.io/>
- CycloneDX: <https://cyclonedx.org/>
- SPDX: <https://spdx.dev/>
- CIS Controls v8.1: <https://www.cisecurity.org/controls/v8-1>
- ISO/IEC 27001:2022: <https://www.iso.org/standard/27001>
- AICPA SOC suite: <https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2>
- FIPS 140-3 / CMVP: <https://csrc.nist.gov/pubs/fips/140-3/final>
- EU AI Act — Regulation (EU) 2024/1689: <http://data.europa.eu/eli/reg/2024/1689/oj>
- NIS2 — Directive (EU) 2022/2555: <http://data.europa.eu/eli/dir/2022/2555/oj>

## Bottom line

BULL already contains a non-trivial set of controls that map credibly to major
security frameworks. Its strongest current evidence is **execution authorization,
least privilege, isolation, controlled information flow, audit integrity,
bounded resource use, and explicit fail-closed behavior**.

The correct claim today is:

> **BULL implements technical controls that align with portions of NIST CSF,
> NIST SP 800-53, NIST AI RMF, NIST SSDF, OWASP LLM Top 10, MITRE ATLAS and CIS
> Controls. Its guest-release pipeline now includes machine-readable CycloneDX
> SBOM generation plus signed SLSA/Sigstore/in-toto attestation and verification
> hooks, but no SLSA level is claimed and no new live release is implied by the
> presence of that workflow. BULL is not independently certified or fully
> compliant with ISO 27001, SOC 2, FIPS 140-3, EU AI Act, NIS2, NIST or the
> other frameworks listed here.**

That statement should be updated whenever the production boundary, release
pipeline, deployment evidence, or external assessment status changes.
