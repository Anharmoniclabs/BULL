# Whole-repository readability record

Baseline: `b6b69d47e6da06f328e719db9f0c2cb85d46ce9f`. This pass accounts for **all 393 tracked files** at that
revision. It is a readability and consistency review, not an independent security
audit or a claim that every line was manually inspected.

## Results

- 172 files clarified; 19 additional files formatted.
- 116 files retained after applicable checks.
- 86 publication, evidence, asset or legal files preserved byte for byte.
- All 188 tracked Python files parsed and were compared structurally. Maintained
  code was formatted; publication/evidence copies stayed unchanged. Module and
  selected class/function docstrings were excluded from the structural comparison.
- All 10 firmware C/header token streams and include order were compared. Two
  host state-machine simulations passed. No hardware flash is implied.
- Browser JavaScript/TypeScript ASTs, HTML DOM/text, CSS values and ordering,
  and JSON/YAML values were compared. The two `.jsonc` templates remain valid
  strict JSON because existing Python tooling reads them with `json.loads`.
- All 12 shell entrypoints passed syntax checks and retain their original bytes.
- All maintained Markdown files were scanned for local links, structure and
  ambiguous evidence claims. Specific descriptions were revised where source
  contradicted them; historical results retain their original identities.

The [machine-readable record](repository-readability.json) includes before/after
hashes for every baseline file. This document and that record are new report
artifacts and do not hash themselves.

## Changes beyond layout

`tools/build_site.py` now registers the existing production router and effect
journal, fixing the baseline site-build failure. Its source-link matcher also
accepts whitespace between HTML attributes, so readable multi-line markup still
resolves to commit-bound links. These are the only executable Python changes in
this extension. Permission checks, effect ordering, policies and report schemas
were preserved.

Prototype descriptions now distinguish recorded quarantine profiles from actual
OS isolation, heuristic model labels from verified identity, and source checks
from deployment evidence. Public API names remain compatible.

## Validation and limits

The initial full suite reported **646 passed, 21 subtests passed, 5 failed and
9 errors**. After the edits it reported **656 passed, 21 subtests passed and
4 failed**, with no skips. Website and audit-configuration checks pass. The
standalone source/API adversarial runner reported **49 held, 0 broken**.
Published paper/source/companion checksums and the 12-transition traceability
check passed. The TLA+ models themselves were unchanged; no new model-checking
result is claimed.

The four failures are retained:

- `test_private_paired_channels`
- `test_bind_private_unix_socket_mode_and_dir`
- `test_accept_authenticated_rejects_foreign_uid`
- `test_bounded_sandbox_output_kills_flooding_workload`

A fresh process independently confirmed that this host denies `AF_UNIX` socket
creation and user-namespace UID mapping. Tests and runtime protections were not
weakened or skipped. Consequently the full source gate is **not PASS on this host**.
KVM and physical approval were not repeated here; `/dev/kvm` is absent. Old passing
guest reports stay attached to their old revisions.

For deployment acceptance, rerun the full suite and the applicable KVM runners
on the clean published commit in the supported Codespace/operator environment.
Use the output's exact source identity; do not relabel an earlier report.

## Per-file accounting

“Retained” means no edit was needed or a format/configuration boundary was kept.
“Preserved” means evidence, publication, asset or legal bytes were deliberately
kept intact. File-level checks do not mean every file has a separate runtime test.

| File | Purpose | Action | Check |
|---|---|---|---|
| [.github/ISSUE_TEMPLATE/bug_report.md](../.github/ISSUE_TEMPLATE/bug_report.md) | Documentation template | Retained | Local-link, structure and claim scan; historical scope retained |
| [.github/ISSUE_TEMPLATE/config.yml](../.github/ISSUE_TEMPLATE/config.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md) | Change | Retained | Local-link, structure and claim scan; historical scope retained |
| [.github/dependabot.yml](../.github/dependabot.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/formal.yml](../.github/workflows/formal.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/freshclam.yml](../.github/workflows/freshclam.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/guest-recipe.yml](../.github/workflows/guest-recipe.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/guest-release.yml](../.github/workflows/guest-release.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/lifecycle-governance-lab.yml](../.github/workflows/lifecycle-governance-lab.yml) | UI, service or workflow configuration | Formatted | Parsed YAML values compared |
| [.github/workflows/microvm.yml](../.github/workflows/microvm.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.github/workflows/pages.yml](../.github/workflows/pages.yml) | UI, service or workflow configuration | Formatted | Parsed YAML values compared |
| [.github/workflows/pytest.yml](../.github/workflows/pytest.yml) | UI, service or workflow configuration | Retained | Parsed YAML values compared |
| [.gitignore](../.gitignore) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [COMPLIANCE.md](../COMPLIANCE.md) | BULL standards and compliance crosswalk | Retained | Local-link, structure and claim scan; historical scope retained |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contributing to BULL | Clarified | Local-link, structure and claim scan; historical scope retained |
| [LICENSE](../LICENSE) | Build, runtime configuration or support file | Preserved | Exact bytes match baseline |
| [README.md](../README.md) | BULL | Clarified | Local-link, structure and claim scan; historical scope retained |
| [SECURITY.md](../SECURITY.md) | Security policy | Retained | Local-link, structure and claim scan; historical scope retained |
| [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Third-party materials | Preserved | Exact bytes match baseline |
| [benchmarks/20260920/attack-summary.csv](../benchmarks/20260920/attack-summary.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [benchmarks/20260920/benchmark.json](../benchmarks/20260920/benchmark.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [benchmarks/20260920/host.txt](../benchmarks/20260920/host.txt) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [benchmarks/20260920/hotpath.csv](../benchmarks/20260920/hotpath.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [certification/open_model_certification.json](../certification/open_model_certification.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [certification/verification.json](../certification/verification.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [compliance/README.md](../compliance/README.md) | BULL assurance control registry | Retained | Local-link, structure and claim scan; historical scope retained |
| [deploy/bull-egress-gateway.service](../deploy/bull-egress-gateway.service) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [deploy/cloudflare-audit/README.md](../deploy/cloudflare-audit/README.md) | BULL Cloudflare audit anchor | Retained | Local-link, structure and claim scan; historical scope retained |
| [deploy/cloudflare-audit/package.json](../deploy/cloudflare-audit/package.json) | UI, service or workflow configuration | Retained | Parsed JSON values compared |
| [deploy/cloudflare-audit/prepare_build.py](../deploy/cloudflare-audit/prepare_build.py) | Prepare a local Wrangler build config; never provision, upload, or deploy. | Clarified | AST comparison; docstrings excluded |
| [deploy/cloudflare-audit/schema.sql](../deploy/cloudflare-audit/schema.sql) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [deploy/cloudflare-audit/src/index.ts](../deploy/cloudflare-audit/src/index.ts) | UI, service or workflow configuration | Formatted | Parsed TypeScript AST compared |
| [deploy/cloudflare-audit/wrangler.jsonc](../deploy/cloudflare-audit/wrangler.jsonc) | UI, service or workflow configuration | Retained | Strict JSON compatibility and values compared |
| [deploy/egress_redirect.nft](../deploy/egress_redirect.nft) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [deploy/install_egress_gateway.sh](../deploy/install_egress_gateway.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [deploy/production-effect-coverage.json](../deploy/production-effect-coverage.json) | UI, service or workflow configuration | Retained | Parsed JSON values compared |
| [docs/ADAPTER_VALIDATION.md](../docs/ADAPTER_VALIDATION.md) | Supported execution paths and recovery evidence | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/BENCHMARK_20260920.md](../docs/BENCHMARK_20260920.md) | BULL red-team benchmark — 2026-09-20 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/BRANCH_AUDIT_20260922.md](../docs/BRANCH_AUDIT_20260922.md) | Branch inventory and claim scope | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/BRANCH_INTEGRATION.md](../docs/BRANCH_INTEGRATION.md) | September 23 branch integration | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/BRAND.md](../docs/BRAND.md) | BULL brand assets | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/CODESPACES_DEPLOYMENT_CHECKS.md](../docs/CODESPACES_DEPLOYMENT_CHECKS.md) | Deployment checks from Codespaces | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/CODESPACES_VM_AND_KEY_CHECKS.md](../docs/CODESPACES_VM_AND_KEY_CHECKS.md) | Run the remaining checks from Codespaces | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/CODE_READING_GUIDE.md](../docs/CODE_READING_GUIDE.md) | Reading BULL's code | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/CONTROL_CONSOLE.md](../docs/CONTROL_CONSOLE.md) | BULL Command / Control Console | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/CROSS_PLATFORM_SECURITY.md](../docs/CROSS_PLATFORM_SECURITY.md) | Cross-platform security architecture | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/DISTRIBUTION.md](../docs/DISTRIBUTION.md) | Source and binary distribution | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/GOVERNED_AGENT_RUN.md](../docs/GOVERNED_AGENT_RUN.md) | Local-model agent, sustained operation, and recovery | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/HARDENING.md](../docs/HARDENING.md) | Hardening components and their boundaries | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/HARDWARE_AUTHORITY.md](../docs/HARDWARE_AUTHORITY.md) | BULL Hardware Authority | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/HUMAN_APPROVAL.md](../docs/HUMAN_APPROVAL.md) | Credentialed approval for consequential operations | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/HUMAN_FIRST_PRODUCTION_ASSURANCE.md](../docs/HUMAN_FIRST_PRODUCTION_ASSURANCE.md) | Human-first production assurance | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/INTEGRATION_QUALIFICATION_20260927.md](../docs/INTEGRATION_QUALIFICATION_20260927.md) | BULL integration candidate and live KVM status — 2026-09-27 UTC | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/LIFECYCLE_CONCERN_COVERAGE.md](../docs/LIFECYCLE_CONCERN_COVERAGE.md) | Owner concern register and implementation coverage | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/LIFECYCLE_GOVERNANCE.md](../docs/LIFECYCLE_GOVERNANCE.md) | BULL lifecycle governance — experimental implementation v0.1 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/LIFECYCLE_VALIDATION_20260926.md](../docs/LIFECYCLE_VALIDATION_20260926.md) | Lifecycle lab validation — 2026-09-26 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/MICROVM_INTEGRATION_REPORT.md](../docs/MICROVM_INTEGRATION_REPORT.md) | Local MicroVM integration result — 2026-09-20 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/MICROVM_R3_FOLLOWUP.md](../docs/MICROVM_R3_FOLLOWUP.md) | Historical R3 follow-up: partial implementation | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/MICROVM_RELEASE_STATUS.md](../docs/MICROVM_RELEASE_STATUS.md) | MicroVM release notes and status | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/OCTOBER_REVIEW.md](../docs/OCTOBER_REVIEW.md) | Technical presentation Q&A | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/PRESENTATION.md](../docs/PRESENTATION.md) | BULL in five minutes | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md](../docs/PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md) | External production audit-anchor evidence — 2026-09-20 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/PRODUCTION_SECURITY.md](../docs/PRODUCTION_SECURITY.md) | BULL production security boundary | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/PUBLICATION.md](../docs/PUBLICATION.md) | BULL publication | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/README.md](../docs/README.md) | Documentation | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/RELEASE_0.2.0rc1.md](../docs/RELEASE_0.2.0rc1.md) | BULL 0.2.0rc1 release candidate | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/REPRODUCIBLE_DEPLOYMENT.md](../docs/REPRODUCIBLE_DEPLOYMENT.md) | Reproduce a BULL deployment with your own authority | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/RESEARCH_STATUS_20260927.md](../docs/RESEARCH_STATUS_20260927.md) | BULL research qualification checkpoint — 2026-09-27 UTC | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/SECURITY_CLAIMS.md](../docs/SECURITY_CLAIMS.md) | Security claims and evidence requirements | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/SESSION_EXPORT_TRUST_BOUNDARIES.md](../docs/SESSION_EXPORT_TRUST_BOUNDARIES.md) | Session reuse, output publication, and host trust | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/SYSTEM_WIDE_EGRESS.md](../docs/SYSTEM_WIDE_EGRESS.md) | Guest egress: gateway and network rules | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/VALIDATION_20260922.md](../docs/VALIDATION_20260922.md) | Candidate validation — 2026-09-22 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/VALIDATION_20260923.md](../docs/VALIDATION_20260923.md) | Validation recorded 2026-09-23 | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/WEBSITE_REDESIGN_MAP.md](../docs/WEBSITE_REDESIGN_MAP.md) | BULL website redesign map | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/WEBSITE_REDESIGN_VALIDATION.md](../docs/WEBSITE_REDESIGN_VALIDATION.md) | Website redesign validation | Retained | Local-link, structure and claim scan; historical scope retained |
| [docs/evidence/branch-integration-20260923.json](../docs/evidence/branch-integration-20260923.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/evidence/candidate-428db9c.json](../docs/evidence/candidate-428db9c.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/evidence/governed-agent-20260922/README.md](../docs/evidence/governed-agent-20260922/README.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/evidence/governed-agent-20260922/source-manifest.json](../docs/evidence/governed-agent-20260922/source-manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/evidence/governed-agent-20260922/summary.json](../docs/evidence/governed-agent-20260922/summary.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/evidence/hardware-20260923/manual-drain.py](../docs/evidence/hardware-20260923/manual-drain.py) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/multiagent.md](../docs/multiagent.md) | BULL Multi-Agent System | Clarified | Local-link, structure and claim scan; historical scope retained |
| [docs/papers/bull-ii/IEEEtran.cls](../docs/papers/bull-ii/IEEEtran.cls) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/LICENSE](../docs/papers/bull-ii/LICENSE) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/README.md](../docs/papers/bull-ii/README.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/SUBMISSION.md](../docs/papers/bull-ii/SUBMISSION.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/build.py](../docs/papers/bull-ii/build.py) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/coverage.json](../docs/papers/bull-ii/coverage.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence-manifest.json](../docs/papers/bull-ii/evidence-manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/ADAPTER_VALIDATION.md](../docs/papers/bull-ii/evidence/docs/ADAPTER_VALIDATION.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/BENCHMARK_20260920.md](../docs/papers/bull-ii/evidence/docs/BENCHMARK_20260920.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/DISTRIBUTION.md](../docs/papers/bull-ii/evidence/docs/DISTRIBUTION.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/GOVERNED_AGENT_RUN.md](../docs/papers/bull-ii/evidence/docs/GOVERNED_AGENT_RUN.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/HARDWARE_AUTHORITY.md](../docs/papers/bull-ii/evidence/docs/HARDWARE_AUTHORITY.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/HUMAN_APPROVAL.md](../docs/papers/bull-ii/evidence/docs/HUMAN_APPROVAL.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/MICROVM_INTEGRATION_REPORT.md](../docs/papers/bull-ii/evidence/docs/MICROVM_INTEGRATION_REPORT.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md](../docs/papers/bull-ii/evidence/docs/PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/SESSION_EXPORT_TRUST_BOUNDARIES.md](../docs/papers/bull-ii/evidence/docs/SESSION_EXPORT_TRUST_BOUNDARIES.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/VALIDATION_20260922.md](../docs/papers/bull-ii/evidence/docs/VALIDATION_20260922.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/VALIDATION_20260923.md](../docs/papers/bull-ii/evidence/docs/VALIDATION_20260923.md) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/evidence/candidate-428db9c.json](../docs/papers/bull-ii/evidence/docs/evidence/candidate-428db9c.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/evidence/governed-agent-20260922/source-manifest.json](../docs/papers/bull-ii/evidence/docs/evidence/governed-agent-20260922/source-manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/evidence/governed-agent-20260922/summary.json](../docs/papers/bull-ii/evidence/docs/evidence/governed-agent-20260922/summary.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/docs/evidence/hardware-20260923/manual-drain.py](../docs/papers/bull-ii/evidence/docs/evidence/hardware-20260923/manual-drain.py) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/attack-summary.csv](../docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/attack-summary.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/benchmark.json](../docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/benchmark.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/hotpath.csv](../docs/papers/bull-ii/evidence/site/data/benchmarks/20260920/hotpath.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/site/data/hardware/20260923-gestures.json](../docs/papers/bull-ii/evidence/site/data/hardware/20260923-gestures.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/site/data/validation/603365e.json](../docs/papers/bull-ii/evidence/site/data/validation/603365e.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/evidence/validation-ab53f56.json](../docs/papers/bull-ii/evidence/validation-ab53f56.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/figures/audit-flow.svg](../docs/papers/bull-ii/figures/audit-flow.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/figures/data-flow.svg](../docs/papers/bull-ii/figures/data-flow.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/figures/kernel-layers.svg](../docs/papers/bull-ii/figures/kernel-layers.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/figures/microvm-io.svg](../docs/papers/bull-ii/figures/microvm-io.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/layout-reference.tex](../docs/papers/bull-ii/layout-reference.tex) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/paper.tex](../docs/papers/bull-ii/paper.tex) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/plot_evidence.py](../docs/papers/bull-ii/plot_evidence.py) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [docs/papers/bull-ii/requirements.txt](../docs/papers/bull-ii/requirements.txt) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [examples/adversary_capture_example.py](../examples/adversary_capture_example.py) | Demo of the BULL adversary capture layer. | Clarified | AST comparison; docstrings excluded |
| [examples/blocked_action.json](../examples/blocked_action.json) | UI, service or workflow configuration | Retained | Parsed JSON values compared |
| [examples/governed-agent/input.txt](../examples/governed-agent/input.txt) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [examples/multiagent_example.py](../examples/multiagent_example.py) | Demo of the BULL multi-agent system. | Clarified | AST comparison; docstrings excluded |
| [examples/safe_action.json](../examples/safe_action.json) | UI, service or workflow configuration | Retained | Parsed JSON values compared |
| [experiments/lifecycle_governance/core.py](../experiments/lifecycle_governance/core.py) | Compatibility import for the standalone lifecycle evidence lab. | Clarified | AST comparison; docstrings excluded |
| [experiments/lifecycle_governance/viewer.html](../experiments/lifecycle_governance/viewer.html) | UI, service or workflow configuration | Formatted | Parsed DOM and text compared; source tests |
| [firmware/CMakeLists.txt](../firmware/CMakeLists.txt) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [firmware/PICO_EXAMPLES_LICENSE.txt](../firmware/PICO_EXAMPLES_LICENSE.txt) | Build, runtime configuration or support file | Preserved | Exact bytes match baseline |
| [firmware/src/boot_button.c](../firmware/src/boot_button.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/src/boot_clicks.c](../firmware/src/boot_clicks.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/src/boot_clicks.h](../firmware/src/boot_clicks.h) | Firmware source | Retained | C tokens and include order compared; host simulations |
| [firmware/src/main.c](../firmware/src/main.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/src/state_machine.c](../firmware/src/state_machine.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/src/state_machine.h](../firmware/src/state_machine.h) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/src/status_pixel.pio](../firmware/src/status_pixel.pio) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [firmware/src/tusb_config.h](../firmware/src/tusb_config.h) | Firmware source | Retained | C tokens and include order compared; host simulations |
| [firmware/src/usb_descriptors.c](../firmware/src/usb_descriptors.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/tests/boot_clicks_test.c](../firmware/tests/boot_clicks_test.c) | Firmware source | Formatted | C tokens and include order compared; host simulations |
| [firmware/tests/state_machine_test.c](../firmware/tests/state_machine_test.c) | Firmware source | Retained | C tokens and include order compared; host simulations |
| [formal/refinement-map.json](../formal/refinement-map.json) | UI, service or workflow configuration | Retained | Parsed JSON values compared |
| [formal/tla/BullApproval.cfg](../formal/tla/BullApproval.cfg) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [formal/tla/BullApproval.tla](../formal/tla/BullApproval.tla) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [formal/tla/BullRuntime.cfg](../formal/tla/BullRuntime.cfg) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [formal/tla/BullRuntime.tla](../formal/tla/BullRuntime.tla) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [formal/tla/BullSessionAudit.cfg](../formal/tla/BullSessionAudit.cfg) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [formal/tla/BullSessionAudit.tla](../formal/tla/BullSessionAudit.tla) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/README.md](../microvm/README.md) | BULL MicroVM launcher | Retained | Local-link, structure and claim scan; historical scope retained |
| [microvm/audit/README.md](../microvm/audit/README.md) | Audit anchor service | Retained | Local-link, structure and claim scan; historical scope retained |
| [microvm/audit/local-test.sh](../microvm/audit/local-test.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [microvm/config/defaults.env](../microvm/config/defaults.env) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/config/deployment.env.example](../microvm/config/deployment.env.example) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/evidence.py](../microvm/evidence.py) | Host-side audit evidence helpers for deployment tests, not guest authority. | Clarified | AST comparison; docstrings excluded |
| [microvm/governance/README.md](../microvm/governance/README.md) | Protected merge rollout | Retained | Local-link, structure and claim scan; historical scope retained |
| [microvm/governance/main-ruleset.json](../microvm/governance/main-ruleset.json) | UI, service or workflow configuration | Formatted | Parsed JSON values compared |
| [microvm/guest/DEPENDENCIES.md](../microvm/guest/DEPENDENCIES.md) | Production guest dependency contract | Retained | Local-link, structure and claim scan; historical scope retained |
| [microvm/guest/build_public.py](../microvm/guest/build_public.py) | Public, pinned guest recipe. No private baseline, service key, or founder path. | Clarified | AST comparison; docstrings excluded |
| [microvm/guest/bull-engine](../microvm/guest/bull-engine) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [microvm/guest/derive_database_layout.py](../microvm/guest/derive_database_layout.py) | Apply the recipe's database alias to a new image without altering its input. | Clarified | AST comparison; docstrings excluded |
| [microvm/guest/engine-adapter.example.sh](../microvm/guest/engine-adapter.example.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [microvm/guest/finalize_build.py](../microvm/guest/finalize_build.py) | Record a completed local guest build and verify original assets remain intact. | Clarified | AST comparison; docstrings excluded |
| [microvm/guest/init](../microvm/guest/init) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [microvm/guest/prepare_build.py](../microvm/guest/prepare_build.py) | Prepare an isolated Buildroot build from the pinned R3 inputs (no downloads). | Clarified | AST comparison; docstrings excluded |
| [microvm/guest/production.fragment](../microvm/guest/production.fragment) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/guest/public/bull_defconfig](../microvm/guest/public/bull_defconfig) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/guest/public/linux.config](../microvm/guest/public/linux.config) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/guest/public/patches/linux/linux.hash](../microvm/guest/public/patches/linux/linux.hash) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [microvm/integration.py](../microvm/integration.py) | KVM integration fixture with disposable TLS or an operator-selected collector. | Clarified | AST comparison; docstrings excluded |
| [microvm/rootfs/build-ext4.sh](../microvm/rootfs/build-ext4.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [microvm/run-bull-microvm.sh](../microvm/run-bull-microvm.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [namespace_certification.py](../namespace_certification.py) | Defines:  | Clarified | AST comparison; docstrings excluded |
| [pyproject.toml](../pyproject.toml) | Build, runtime configuration or support file | Clarified | Only formatter settings added; package configuration retained |
| [site/README.md](../site/README.md) | BULL engineering website | Retained | Local-link, structure and claim scan; historical scope retained |
| [site/assets/architecture/audit-flow.svg](../site/assets/architecture/audit-flow.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/architecture/data-flow.svg](../site/assets/architecture/data-flow.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/architecture/kernel-layers.svg](../site/assets/architecture/kernel-layers.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/architecture/microvm-io.svg](../site/assets/architecture/microvm-io.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/architecture/overview.svg](../site/assets/architecture/overview.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/benchmarks/attack-latency.svg](../site/assets/benchmarks/attack-latency.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/benchmarks/attack-memory.svg](../site/assets/benchmarks/attack-memory.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/benchmarks/attack-pass-rate.svg](../site/assets/benchmarks/attack-pass-rate.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/benchmarks/hotpath-throughput.svg](../site/assets/benchmarks/hotpath-throughput.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-approved-sheet.png](../site/assets/brand/bull-approved-sheet.png) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-brand-board.svg](../site/assets/brand/bull-brand-board.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-favicon.svg](../site/assets/brand/bull-favicon.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-mark.png](../site/assets/brand/bull-mark.png) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-mark.svg](../site/assets/brand/bull-mark.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-one-color.svg](../site/assets/brand/bull-one-color.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-primary-dark.svg](../site/assets/brand/bull-primary-dark.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-primary.png](../site/assets/brand/bull-primary.png) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-primary.svg](../site/assets/brand/bull-primary.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/bull-stacked.svg](../site/assets/brand/bull-stacked.svg) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/brand/manifest.json](../site/assets/brand/manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/explainer/captions.vtt](../site/assets/explainer/captions.vtt) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/explainer/chapters.json](../site/assets/explainer/chapters.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/explainer/manifest.json](../site/assets/explainer/manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/archive/bull-ii-prior.pdf](../site/assets/papers/archive/bull-ii-prior.pdf) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/bull-ii-companion.zip](../site/assets/papers/bull-ii-companion.zip) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/bull-ii-manifest.json](../site/assets/papers/bull-ii-manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/bull-ii.pdf](../site/assets/papers/bull-ii.pdf) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/bull.pdf](../site/assets/papers/bull.pdf) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/assets/papers/manifest.json](../site/assets/papers/manifest.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/benchmarks/20260920/attack-summary.csv](../site/data/benchmarks/20260920/attack-summary.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/benchmarks/20260920/benchmark.json](../site/data/benchmarks/20260920/benchmark.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/benchmarks/20260920/hotpath.csv](../site/data/benchmarks/20260920/hotpath.csv) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/hardware/20260923-gestures.json](../site/data/hardware/20260923-gestures.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/validation/603365e.json](../site/data/validation/603365e.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/data/validation/ab53f56.json](../site/data/validation/ab53f56.json) | Retained evidence, publication or design asset | Preserved | Exact bytes match baseline |
| [site/index.html](../site/index.html) | UI, service or workflow configuration | Formatted | Parsed DOM and text compared; source tests |
| [site/infrastructure.js](../site/infrastructure.js) | UI, service or workflow configuration | Formatted | Parsed JavaScript AST compared |
| [site/styles.css](../site/styles.css) | UI, service or workflow configuration | Formatted | CSS selectors, values and ordering compared |
| [src/bulldog/__init__.py](../src/bulldog/__init__.py) | BULL model-agnostic AI execution-governance runtime. | Retained | AST comparison; docstrings excluded |
| [src/bulldog/_namespace_launcher.sh](../src/bulldog/_namespace_launcher.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [src/bulldog/adversary/__init__.py](../src/bulldog/adversary/__init__.py) | Experimental observation records and heuristic grouping of agent responses. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/contracts.py](../src/bulldog/adversary/contracts.py) | Shared contracts for the BULL adversary-capture layer. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/fingerprint.py](../src/bulldog/adversary/fingerprint.py) | Score response phrases against a small model-family signature corpus. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/lure.py](../src/bulldog/adversary/lure.py) | Send diagnostic prompts through a supplied callback and parse claimed tasks. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/quarantine.py](../src/bulldog/adversary/quarantine.py) | Record a proposed isolation profile for each observed finding. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/registry.py](../src/bulldog/adversary/registry.py) | Store observations and group similar claimed task text. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/adversary/system.py](../src/bulldog/adversary/system.py) | Combine callback probes, phrase scoring, task parsing and observation records. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/advisory.py](../src/bulldog/advisory.py) | Advisory recommendations derived from a policy result; no execution authority. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/agent_sentinel.py](../src/bulldog/agent_sentinel.py) | Score environment, process, input-timing and I/O observations for operator review. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/anchor_service.py](../src/bulldog/anchor_service.py) | Durable authenticated audit checkpoints; serve behind a trusted TLS proxy. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/approval.py](../src/bulldog/approval.py) | Durable one-use consequential-action approval, owned by the trusted host. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/approval_cli.py](../src/bulldog/approval_cli.py) | Operator CLI: export/cancel a pending request; signing is a separate ceremony. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/approval_crypto.py](../src/bulldog/approval_crypto.py) | OpenSSH security-key signature verification; no software-key fallback. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/assurance.py](../src/bulldog/assurance.py) | Evaluate the control registry against source and deployment evidence. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/audit.py](../src/bulldog/audit.py) | Append and verify audit records, checkpoint their heads, and retain failures. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/audit_transport.py](../src/bulldog/audit_transport.py) | Versioned production anchor transports with authenticated acknowledgements. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/bootstrap.py](../src/bulldog/bootstrap.py) | Prepare private operator state and launch the local console. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/broker_hardening.py](../src/bulldog/broker_hardening.py) | Additional broker socket and peer checks for explicitly integrated callers. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/canonicalizer.py](../src/bulldog/canonicalizer.py) | Normalize requested resources before policy evaluation and command binding. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/cgroup_scope.py](../src/bulldog/cgroup_scope.py) | Place workloads in delegated cgroups and manage their resource limits. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/cli.py](../src/bulldog/cli.py) | Parse operator commands and call the corresponding BULL entry points. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/console_static/app.js](../src/bulldog/console_static/app.js) | UI, service or workflow configuration | Formatted | Parsed JavaScript AST compared |
| [src/bulldog/console_static/bull-mark.svg](../src/bulldog/console_static/bull-mark.svg) | Build, runtime configuration or support file | Retained | Exact bytes match baseline; category and text/format scan |
| [src/bulldog/console_static/index.html](../src/bulldog/console_static/index.html) | UI, service or workflow configuration | Formatted | Parsed DOM and text compared; source tests |
| [src/bulldog/console_static/styles.css](../src/bulldog/console_static/styles.css) | UI, service or workflow configuration | Formatted | CSS selectors, values and ordering compared |
| [src/bulldog/container_hardening.py](../src/bulldog/container_hardening.py) | Check selected launcher text and Linux namespace state. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/control_plane.py](../src/bulldog/control_plane.py) | Serve the operator console and its bounded local control API. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/data/assurance_controls.json](../src/bulldog/data/assurance_controls.json) | UI, service or workflow configuration | Formatted | Parsed JSON values compared |
| [src/bulldog/dispatcher.py](../src/bulldog/dispatcher.py) | Bind requests to operations before calling runtime or broker methods. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/effect_journal.py](../src/bulldog/effect_journal.py) | Durable host-owned journal for consequential external effects. | Retained | AST comparison; docstrings excluded |
| [src/bulldog/egress_gateway.py](../src/bulldog/egress_gateway.py) | Handle HTTP, TLS server-name and DNS requests in a configured guest. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/egress_proxy.py](../src/bulldog/egress_proxy.py) | Authorize outbound broker requests over a local socket. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/engine.py](../src/bulldog/engine.py) | Evaluate actions against policy and retained session history. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/filesystem_manifest.py](../src/bulldog/filesystem_manifest.py) | Describe bounded project contents for workspace admission. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/guest_engine.py](../src/bulldog/guest_engine.py) | One-shot trusted guest supervisor; workload authority is deployment-owned. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/guest_preflight.py](../src/bulldog/guest_preflight.py) | Fail-closed guest dependency check, before admitting any workload. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/__init__.py](../src/bulldog/hardware_approval/__init__.py) | BULL Hardware Authority protocol (prototype; not a FIDO authenticator). | Retained | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/cli.py](../src/bulldog/hardware_approval/cli.py) | Operator diagnostics and disabled public enrollment records; no software YES. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/diagnostic.py](../src/bulldog/hardware_approval/diagnostic.py) | Read the KB2040 diagnostic HID; never constructs approval proofs. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/protocol.py](../src/bulldog/hardware_approval/protocol.py) | Bounded, fixed-width network-byte-order BULL-AUTH-1 encoding. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/provider.py](../src/bulldog/hardware_approval/provider.py) | Custom secure-element assertions for the existing durable ApprovalGate. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/hardware_approval/verifier.py](../src/bulldog/hardware_approval/verifier.py) | Stateless assertion verification. Durable consumption belongs in ApprovalGate. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/host_certify.py](../src/bulldog/host_certify.py) | Probe host prerequisites and collect live sandbox attestation. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/integrity.py](../src/bulldog/integrity.py) | Sign and verify the trusted runtime file manifest. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/landlock_policy.py](../src/bulldog/landlock_policy.py) | Install the Linux Landlock filesystem restrictions used by the sandbox. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/lifecycle_bridge.py](../src/bulldog/lifecycle_bridge.py) | Host-owned, single-command bridge from lifecycle admission to production dispatch. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/lifecycle_governance.py](../src/bulldog/lifecycle_governance.py) | Experimental, host-side lifecycle gate. Not a production runtime replacement. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/linux_sandbox.py](../src/bulldog/linux_sandbox.py) | Linux isolation helpers for mounts, privileges and syscall restrictions. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/malware_scanner.py](../src/bulldog/malware_scanner.py) | Run bounded ClamAV scans and report missing or failed scanning requirements. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/microvm.py](../src/bulldog/microvm.py) | Hardware-only MicroVM launcher. Deployment configuration is data, never code. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/microvm_image.py](../src/bulldog/microvm_image.py) | Build a no-clobber root filesystem from a bounded admitted tree. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/microvm_protocol.py](../src/bulldog/microvm_protocol.py) | Bounded, authenticated, ordered messages for one trusted MicroVM session. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/models.py](../src/bulldog/models.py) | Shared action, capability, provenance and decision data structures. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/__init__.py](../src/bulldog/multiagent/__init__.py) | Development orchestration with registered host callables and policy checks. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/agents.py](../src/bulldog/multiagent/agents.py) | Coordinator, policy, executor and output-checking roles for development runs. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/bus.py](../src/bulldog/multiagent/bus.py) | Capability-checked message bus for the BULL multi-agent system. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/contracts.py](../src/bulldog/multiagent/contracts.py) | Shared contracts for the BULL multi-agent system. | Retained | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/honeytoken.py](../src/bulldog/multiagent/honeytoken.py) | Host-owned canary monitoring for the BULL multi-agent layer. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/multiagent/system.py](../src/bulldog/multiagent/system.py) | Top-level orchestrator for the BULL multi-agent system. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/namespace_sandbox.py](../src/bulldog/namespace_sandbox.py) | Launch a bounded Linux namespace workload and verify its startup attestation. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/pinned_egress.py](../src/bulldog/pinned_egress.py) | Validate and pin outbound destinations before connecting. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/policy.py](../src/bulldog/policy.py) | Evaluate capabilities and provenance to produce a policy decision. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/policy_bundle.py](../src/bulldog/policy_bundle.py) | Load signed policy bundles and validate their capability ceilings. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/production_gate.py](../src/bulldog/production_gate.py) | Reject production startup when required deployment protections are absent. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/production_router.py](../src/bulldog/production_router.py) | Single fail-closed entrypoint for agent-facing production effects. | Retained | AST comparison; docstrings excluded |
| [src/bulldog/profiles.py](../src/bulldog/profiles.py) | Assemble production runtime checks and mediate execution and broker effects. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/qualification.py](../src/bulldog/qualification.py) | Validate private KVM reports and return bounded summaries for the console. | Retained | AST comparison; docstrings excluded |
| [src/bulldog/release_evidence.py](../src/bulldog/release_evidence.py) | Validate release inventories, digests and provenance verification evidence. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/resource_limits.py](../src/bulldog/resource_limits.py) | Describe and apply bounded workload resource settings. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/run_egress_gateway.py](../src/bulldog/run_egress_gateway.py) | Guest entrypoint for the transparent egress gateway. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/runtime.py](../src/bulldog/runtime.py) | Execute admitted operations and record their runtime results. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/sandbox_backends.py](../src/bulldog/sandbox_backends.py) | Cross-platform sandbox backend contract. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/seccomp_policy.py](../src/bulldog/seccomp_policy.py) | Build and install syscall filters for the supported sandbox profiles. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/secret_broker.py](../src/bulldog/secret_broker.py) | Authorize named secret retrieval through a local broker protocol. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/secure_fs.py](../src/bulldog/secure_fs.py) | Open paths with containment and symlink checks for trusted filesystem access. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/security_domain.py](../src/bulldog/security_domain.py) | Track host-owned security domains, delegation, grants and revocation. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/semantic_intent.py](../src/bulldog/semantic_intent.py) | Deterministic semantic intent gate for BULL. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/session_guard.py](../src/bulldog/session_guard.py) | Retain session behavior used when evaluating subsequent action requests. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/snapshot.py](../src/bulldog/snapshot.py) | Create admitted workspace snapshots before workload execution. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/snapshot_worker.py](../src/bulldog/snapshot_worker.py) | Run snapshot admission work in a separate constrained process. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/socket_hardening.py](../src/bulldog/socket_hardening.py) | Bind private Unix sockets and check the credentials of connecting peers. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/token_broker.py](../src/bulldog/token_broker.py) | Prototype in-memory secret vault and scoped, expiring proxy tokens. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/trace_model.py](../src/bulldog/trace_model.py) | Executable state-machine abstraction for runtime trace checks. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/trace_runtime.py](../src/bulldog/trace_runtime.py) | Convert runtime events into the trace model used by bounded checks. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/verify.py](../src/bulldog/verify.py) | Check retained audit evidence and report consistency failures. | Clarified | AST comparison; docstrings excluded |
| [src/bulldog/workspace_limits.py](../src/bulldog/workspace_limits.py) | Define bounded file, byte and path limits for workspace admission. | Clarified | AST comparison; docstrings excluded |
| [tests/redteam_local_host/test_brokers_and_environment.py](../tests/redteam_local_host/test_brokers_and_environment.py) | Test fixture: _PeerSocket, test_secret_broker_rejects_wrong_unix_peer_uid, test_egress_broker_rejects_wrong_unix_peer_uid | Retained | AST comparison; docstrings excluded |
| [tests/redteam_local_host/test_production_entrypoints.py](../tests/redteam_local_host/test_production_entrypoints.py) | Test fixture: _exec_action, test_legacy_production_boolean_is_rejected, test_development_runtime_is_loudly_marked_unsafe | Retained | AST comparison; docstrings excluded |
| [tests/redteam_local_host/test_snapshot_worker.py](../tests/redteam_local_host/test_snapshot_worker.py) | Test fixture: test_isolated_snapshot_worker_returns_read_only_bounded_snapshot | Clarified | AST comparison; docstrings excluded |
| [tests/redteam_local_host/test_workspace_admission.py](../tests/redteam_local_host/test_workspace_admission.py) | Test fixture: _budget, test_file_count_budget_fails_closed, test_total_byte_budget_fails_closed | Retained | AST comparison; docstrings excluded |
| [tests/redteam_multiagent/test_honeytoken_canary.py](../tests/redteam_multiagent/test_honeytoken_canary.py) | Safe red-team regressions for the multi-agent honeytoken boundary. | Clarified | AST comparison; docstrings excluded |
| [tests/redteam_multiagent/test_redteam_bypass.py](../tests/redteam_multiagent/test_redteam_bypass.py) | Red-team regression tests for the bulldog multi-agent system. | Clarified | AST comparison; docstrings excluded |
| [tests/test_adversary_capture.py](../tests/test_adversary_capture.py) | Tests for the bulldog adversary capture layer. | Clarified | AST comparison; docstrings excluded |
| [tests/test_advisory_monotonicity.py](../tests/test_advisory_monotonicity.py) | Test fixture: FixedAdvisory, _action, test_advisory_allow_cannot_lower_sandbox_policy | Clarified | AST comparison; docstrings excluded |
| [tests/test_anchor_service.py](../tests/test_anchor_service.py) | Test fixture: record, setup_store, test_durable_restart_exact_retry_and_conflict | Clarified | AST comparison; docstrings excluded |
| [tests/test_approved_brand.py](../tests/test_approved_brand.py) | Verify the approved B-shaped bulldog, not a substitute logo or external image. | Clarified | AST comparison; docstrings excluded |
| [tests/test_assurance.py](../tests/test_assurance.py) | Test fixture: test_registry_is_unique_and_profile_references_are_valid, test_missing_deployment_evidence_never_becomes_pass, test_dynamic_attestation_maps_to_required_sandbox_controls | Clarified | AST comparison; docstrings excluded |
| [tests/test_audit_fail_closed.py](../tests/test_audit_fail_closed.py) | Test fixture: action, build, AuditFailClosedTests | Retained | AST comparison; docstrings excluded |
| [tests/test_audit_integrity.py](../tests/test_audit_integrity.py) | Test fixture: action, build, AuditIntegrityTests | Retained | AST comparison; docstrings excluded |
| [tests/test_benchmark_site.py](../tests/test_benchmark_site.py) | Test fixture: test_benchmark_publication_contract | Clarified | AST comparison; docstrings excluded |
| [tests/test_bootstrap.py](../tests/test_bootstrap.py) | Test fixture: BootstrapTests | Clarified | AST comparison; docstrings excluded |
| [tests/test_brand_site.py](../tests/test_brand_site.py) | Read-only publication contracts. These checks do not run or certify a VM. | Clarified | AST comparison; docstrings excluded |
| [tests/test_canonicalizer_paths_v2.py](../tests/test_canonicalizer_paths_v2.py) | Test fixture: _canonicalize, test_traversal_never_classifies_as_project, test_project_path_is_canonicalized_before_classification | Clarified | AST comparison; docstrings excluded |
| [tests/test_cgroup_check.py](../tests/test_cgroup_check.py) | Validation logic under real optimized interpreters; no isolation claims from mocks. | Clarified | AST comparison; docstrings excluded |
| [tests/test_cloudflare_audit_anchor_contract.py](../tests/test_cloudflare_audit_anchor_contract.py) | Test fixture: test_cloudflare_anchor_files_and_route_contract, test_build_config_uses_explicit_existing_database_without_changing_template, test_build_config_refuses_missing_or_placeholder_d | Clarified | AST comparison; docstrings excluded |
| [tests/test_control_plane.py](../tests/test_control_plane.py) | Test fixture: ControlPlaneTests | Clarified | AST comparison; docstrings excluded |
| [tests/test_deployment_checks.py](../tests/test_deployment_checks.py) | Validation-runner contracts. Fixtures here do not qualify hardware or KVM. | Clarified | AST comparison; docstrings excluded |
| [tests/test_deployment_setup.py](../tests/test_deployment_setup.py) | Independent installation evidence, with no founder/service credentials. | Clarified | AST comparison; docstrings excluded |
| [tests/test_effect_journal.py](../tests/test_effect_journal.py) | Test fixture: journal, test_effect_is_dispatched_at_most_once_and_exact_bytes_are_bound, test_uncertain_effect_requires_observation_and_never_retries | Clarified | AST comparison; docstrings excluded |
| [tests/test_egress_gateway.py](../tests/test_egress_gateway.py) | End-to-end tests for bulldog.egress_gateway (real sockets, real TLS). | Clarified | AST comparison; docstrings excluded |
| [tests/test_egress_lifecycle.py](../tests/test_egress_lifecycle.py) | Repeat benign broker requests through a controlled transport fixture. | Clarified | AST comparison; docstrings excluded |
| [tests/test_egress_trace.py](../tests/test_egress_trace.py) | Test fixture: test_egress_broker_emits_single_grant, test_empty_egress_broker_has_no_grant, test_duplicate_broker_grant_remains_illegal | Clarified | AST comparison; docstrings excluded |
| [tests/test_full_argv_and_production_wiring.py](../tests/test_full_argv_and_production_wiring.py) | Test fixture: CleanScanner, RecordingSandbox, test_namespace_backend_defaults_to_read_only | Clarified | AST comparison; docstrings excluded |
| [tests/test_fuzz_boundaries.py](../tests/test_fuzz_boundaries.py) | Test fixture: _random_text, test_random_model_metadata_cannot_override_trusted_identity, test_random_illegal_trace_transitions_fail_closed | Clarified | AST comparison; docstrings excluded |
| [tests/test_governed_agent.py](../tests/test_governed_agent.py) | Test fixture: test_untrusted_proposal_cannot_add_authority, test_complete_read_only_tool_surface, event | Clarified | AST comparison; docstrings excluded |
| [tests/test_guest_engine.py](../tests/test_guest_engine.py) | Test fixture: authority, test_authority_rejects_tampering_and_expiry, test_expired_authority_is_not_admitted | Clarified | AST comparison; docstrings excluded |
| [tests/test_guest_preflight.py](../tests/test_guest_preflight.py) | Dependency failure tests; never reported as guest/KVM execution evidence. | Clarified | AST comparison; docstrings excluded |
| [tests/test_hardening_additions.py](../tests/test_hardening_additions.py) | Regression tests for the hardening additions commit. | Clarified | AST comparison; docstrings excluded |
| [tests/test_hardware_authority.py](../tests/test_hardware_authority.py) | Software-generated keys are confined to tests; these do not attest hardware. | Clarified | AST comparison; docstrings excluded |
| [tests/test_hardware_diagnostic.py](../tests/test_hardware_diagnostic.py) | USB transport simulations, not physical presence or signing evidence. | Clarified | AST comparison; docstrings excluded |
| [tests/test_hardware_gate.py](../tests/test_hardware_gate.py) | Real P-256 signatures and durable gate/dispatcher checks; synthetic test keys only. | Clarified | AST comparison; docstrings excluded |
| [tests/test_human_approval.py](../tests/test_human_approval.py) | Deterministic approval conformance tests with real OpenSSH verification. | Clarified | AST comparison; docstrings excluded |
| [tests/test_lifecycle_bridge.py](../tests/test_lifecycle_bridge.py) | A real lifecycle admission reaches only the host-bound production adapter. | Clarified | AST comparison; docstrings excluded |
| [tests/test_lifecycle_governance.py](../tests/test_lifecycle_governance.py) | Tests execute the new module directly; no production backend is substituted. | Clarified | AST comparison; docstrings excluded |
| [tests/test_lifecycle_lab.py](../tests/test_lifecycle_lab.py) | Test fixture: test_real_fixture_and_read_only_report, test_evidence_fields_cannot_inject_html | Clarified | AST comparison; docstrings excluded |
| [tests/test_microvm.py](../tests/test_microvm.py) | Host-only regressions; these tests do not claim a hardware boot. | Clarified | AST comparison; docstrings excluded |
| [tests/test_microvm_protocol.py](../tests/test_microvm_protocol.py) | Test fixture: channels, test_roundtrip_workload_text_is_only_payload, test_authenticated_wrong_session_sequence_or_operation_rejected | Clarified | AST comparison; docstrings excluded |
| [tests/test_multiagent.py](../tests/test_multiagent.py) | Tests for the bulldog multi-agent system. | Retained | AST comparison; docstrings excluded |
| [tests/test_policy.py](../tests/test_policy.py) | Test fixture: BulldogPolicyTests | Retained | AST comparison; docstrings excluded |
| [tests/test_policy_hardening.py](../tests/test_policy_hardening.py) | Test fixture: BulldogHardeningTests | Retained | AST comparison; docstrings excluded |
| [tests/test_policy_hardening_v2.py](../tests/test_policy_hardening_v2.py) | Test fixture: request, HardenedPolicyTests | Retained | AST comparison; docstrings excluded |
| [tests/test_production_boundary.py](../tests/test_production_boundary.py) | Test fixture: _attestation, test_security_bootstrap_never_imports_from_agent_workspace, test_backend_attestation_is_nonce_bound_and_strict | Retained | AST comparison; docstrings excluded |
| [tests/test_production_router.py](../tests/test_production_router.py) | Test fixture: router, request, test_unknown_effect_is_unreachable | Clarified | AST comparison; docstrings excluded |
| [tests/test_public_guest_recipe.py](../tests/test_public_guest_recipe.py) | Recipe rejection tests; actual upstream Kconfig configuration is a CI job. | Clarified | AST comparison; docstrings excluded |
| [tests/test_qualification.py](../tests/test_qualification.py) | Test fixture: test_private_kvm_reports_are_bound_and_sanitized, test_offline_guest_report_is_source_bound_and_gateway_unclaimed, test_networked_gateway_lab_is_source_bound_and_separate_from_ | Clarified | AST comparison; docstrings excluded |
| [tests/test_recovery_failures.py](../tests/test_recovery_failures.py) | Controlled storage faults and disposable collector restart; no host reboot. | Clarified | AST comparison; docstrings excluded |
| [tests/test_redteam_authorization_binding.py](../tests/test_redteam_authorization_binding.py) | Test fixture: CleanScanner, RecordingSandbox, FixedDecisionEngine | Clarified | AST comparison; docstrings excluded |
| [tests/test_redteam_sandbox_decision_bypass.py](../tests/test_redteam_sandbox_decision_bypass.py) | Regression: Decision.SANDBOX must not pass the legacy broker gate. | Clarified | AST comparison; docstrings excluded |
| [tests/test_refinement_map.py](../tests/test_refinement_map.py) | Test fixture: test_refinement_map_covers_python_and_tla_names | Clarified | AST comparison; docstrings excluded |
| [tests/test_release_evidence.py](../tests/test_release_evidence.py) | Test fixture: _bundle, _release_fixture, test_release_evidence_inventory_and_attestation_structure | Clarified | AST comparison; docstrings excluded |
| [tests/test_release_workflow_assurance.py](../tests/test_release_workflow_assurance.py) | Test fixture: test_guest_release_requires_sbom_provenance_and_verification, test_guest_release_final_inventory_is_verified_before_release, test_release_verifies_supplied_bundles_and_pins_sou | Clarified | AST comparison; docstrings excluded |
| [tests/test_repository_artifacts.py](../tests/test_repository_artifacts.py) | Keep locally built VM assets out of the Git index (no VM boot required). | Clarified | AST comparison; docstrings excluded |
| [tests/test_runtime_enforcement_v2.py](../tests/test_runtime_enforcement_v2.py) | Test fixture: AllowEngine, MutatingCleanScanner, CapturingSandbox | Clarified | AST comparison; docstrings excluded |
| [tests/test_sandbox_backends.py](../tests/test_sandbox_backends.py) | Test fixture: test_policy_rejects_invalid_network_mode, test_policy_rejects_direct_secret_grant, test_policy_rejects_nonpositive_output_limit | Retained | AST comparison; docstrings excluded |
| [tests/test_security_domains.py](../tests/test_security_domains.py) | Test fixture: _FakeRuntime, _FakeEgress, _AllowEngine | Clarified | AST comparison; docstrings excluded |
| [tests/test_semantic_intent.py](../tests/test_semantic_intent.py) | Tests for bulldog.semantic_intent (deterministic, fail-closed). | Clarified | AST comparison; docstrings excluded |
| [tests/test_session_guard.py](../tests/test_session_guard.py) | Test fixture: action, SessionEnforcementTests | Clarified | AST comparison; docstrings excluded |
| [tests/test_site_module_map.py](../tests/test_site_module_map.py) | Publication module identities must retain package paths and fail on drift. | Clarified | AST comparison; docstrings excluded |
| [tests/test_snapshot_content.py](../tests/test_snapshot_content.py) | Test fixture: test_directory_storage_size_is_not_content_but_file_size_is | Clarified | AST comparison; docstrings excluded |
| [tests/test_token_broker.py](../tests/test_token_broker.py) | Tests for bulldog.token_broker (real crypto paths, fail-closed). | Clarified | AST comparison; docstrings excluded |
| [tools/adversarial_check.py](../tools/adversarial_check.py) | BULL adversarial test — single-file command-line tool. | Clarified | AST comparison; docstrings excluded |
| [tools/audit_governed_agent.py](../tools/audit_governed_agent.py) | Offline evidence validation. Chain consistency is not independent anchoring proof. | Clarified | AST comparison; docstrings excluded |
| [tools/build_brand_assets.py](../tools/build_brand_assets.py) | Rebuild BULL artwork from the exact owner-approved PNG, without network access. | Clarified | AST comparison; docstrings excluded |
| [tools/build_external_review_manifest.py](../tools/build_external_review_manifest.py) | Create a public, hash-only handoff manifest for an independent BULL review. | Clarified | AST comparison; docstrings excluded |
| [tools/build_site.py](../tools/build_site.py) | Build BULL's read-only engineering publication from tracked source files. | Clarified | AST comparison with two declared site fixes; site tests |
| [tools/bull-production-provision.sh](../tools/bull-production-provision.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [tools/cgroup_check.py](../tools/cgroup_check.py) | Small real-kernel resource probes; never run workloads as root. | Clarified | AST comparison; docstrings excluded |
| [tools/check_agent_cgroup.py](../tools/check_agent_cgroup.py) | Harmless live check that a dedicated cgroup refuses a fork at its process limit. | Clarified | AST comparison; docstrings excluded |
| [tools/check_agent_dispatch.py](../tools/check_agent_dispatch.py) | Exercise both fixed agent tools and an empty-grant denial on a real deployment. | Clarified | AST comparison; docstrings excluded |
| [tools/check_governed_agent.py](../tools/check_governed_agent.py) | Run dedicated worker crash/recovery cases and a measured local-model soak. | Clarified | AST comparison; docstrings excluded |
| [tools/check_lifecycle_browser.py](../tools/check_lifecycle_browser.py) | Offline Chromium render checks; HTTP endpoint behavior is tested separately. | Clarified | AST comparison; docstrings excluded |
| [tools/check_package.py](../tools/check_package.py) | Build the committed source distribution and exercise its wheel in a fresh venv. | Clarified | AST comparison; docstrings excluded |
| [tools/check_tla_refinement_map.py](../tools/check_tla_refinement_map.py) | Fail when the TLA/Python transition traceability map drifts. | Clarified | AST comparison; docstrings excluded |
| [tools/deployment_check.py](../tools/deployment_check.py) | Run BULL deployment checks where invoked, including inside a Codespace. | Clarified | AST comparison; docstrings excluded |
| [tools/deployment_setup.py](../tools/deployment_setup.py) | Prepare operator-owned BULL deployments without shared keys or machine paths. | Clarified | AST comparison; docstrings excluded |
| [tools/egress_namespace_lab.py](../tools/egress_namespace_lab.py) | Disposable network-namespace probe for BULL's nftables egress recipe. | Clarified | AST comparison; docstrings excluded |
| [tools/fetch_guest_databases.sh](../tools/fetch_guest_databases.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [tools/gateway_guest_init.sh](../tools/gateway_guest_init.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [tools/gateway_guest_probe.py](../tools/gateway_guest_probe.py) | Run only inside the disposable KVM gateway lab guest. | Retained | AST comparison; docstrings excluded |
| [tools/gateway_systemd_network.sh](../tools/gateway_systemd_network.sh) | Build, runtime configuration or support file | Retained | Shell syntax checked; bytes unchanged |
| [tools/governed_agent.py](../tools/governed_agent.py) | Bounded local-model agent, real production dispatch, durable audit recovery. | Clarified | AST comparison; docstrings excluded |
| [tools/hardware_approval_check.py](../tools/hardware_approval_check.py) | Interactive harmless approval ceremony on an operator's enrolled device. | Clarified | AST comparison; docstrings excluded |
| [tools/hardware_diagnostic.py](../tools/hardware_diagnostic.py) | Compatibility entrypoint for the packaged diagnostic; never grants approval. | Clarified | AST comparison; docstrings excluded |
| [tools/host_setup.py](../tools/host_setup.py) | Administrator provisioning of a BULL cgroup and optional KVM group access. | Clarified | AST comparison; docstrings excluded |
| [tools/release_check.py](../tools/release_check.py) | Collect source validation evidence; never equate it with certification. | Clarified | AST comparison; docstrings excluded |
| [tools/run_assurance_campaign.py](../tools/run_assurance_campaign.py) | Run a source-bound long-duration qualification probe and checkpoint evidence. | Retained | AST comparison; docstrings excluded |
| [tools/run_codespace_combined_candidate_kvm.py](../tools/run_codespace_combined_candidate_kvm.py) | Run the networked bullagent + bullgw + nftables + systemd KVM candidate. | Retained | AST comparison; docstrings excluded |
| [tools/run_codespace_gateway_kvm.py](../tools/run_codespace_gateway_kvm.py) | Build and boot a disposable networked KVM guest for the actual BULL gateway. | Retained | AST comparison; docstrings excluded |
| [tools/run_codespace_gateway_systemd_kvm.py](../tools/run_codespace_gateway_systemd_kvm.py) | Qualify actual BULL systemd gateway units in a separate networked KVM candidate. | Retained | AST comparison; docstrings excluded |
| [tools/run_codespace_kvm.py](../tools/run_codespace_kvm.py) | Prepare a pinned guest and run BULL's five real-KVM cases, or report why blocked. | Clarified | AST comparison; docstrings excluded |
| [tools/run_lifecycle_lab.py](../tools/run_lifecycle_lab.py) | Run actual disposable lifecycle fixtures; serve only a read-only evidence page. | Clarified | AST comparison; docstrings excluded |
| [wrangler.jsonc](../wrangler.jsonc) | UI, service or workflow configuration | Retained | Strict JSON compatibility and values compared |
