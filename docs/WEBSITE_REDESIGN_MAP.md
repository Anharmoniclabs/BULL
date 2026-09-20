# BULL website redesign map

Base: 01cd259. Prepared before implementation. Preserve all source copy and evidence; add an editorial overview and manuscript.

## Visual reference

The supplied YouTube Short opened, but video frames were not reliably available in this environment. No frame-by-frame fidelity is claimed. The explicit written brief drives the design: warm neutral ground, ink typography, restrained teal, oversized title, asymmetric hero, generous spacing, thin rules, softly rounded panels, diagram layering, subtle entrances and no scroll-jacking. System fonts; no external font requests.

## Design system

Responsive display type; 8px-derived spacing; 4/12/24/32px radii; light surfaces with a dark architecture panel. Mobile stacks cards and keeps tables in labeled horizontal scroll regions. Motion is decorative and disabled under reduced motion.

## How BULL handles an agent’s request.

- Current ID: `intro`.
- Purpose and important copy: preserve the existing intro explanation and qualifications.
- Source data / important evidence: Introductory source-based description.
- Current structure: text introduction.
- Proposed structure: asymmetric display headline, bulldog architectural object, three CTAs.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## From information to controlled execution.

- Current ID: `explainer`.
- Purpose and important copy: preserve the existing explainer explanation and qualifications.
- Source data / important evidence: `https://d2ol7oe51mr4n9.cloudfront.net/user_3BN6e9xn2X4STcw4FAYAt0XmfjE/e32608c9-1342-464e-b623-9df5600ae8dd.mp4`, `./assets/explainer/captions.vtt`, `./transcript.html`, `https://d2ol7oe51mr4n9.cloudfront.net/user_3BN6e9xn2X4STcw4FAYAt0XmfjE/e32608c9-1342-464e-b623-9df5600ae8dd.mp4`, `./assets/explainer/manifest.json`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## A convincing request is still just a request.

- Current ID: `story`.
- Purpose and important copy: preserve the existing story explanation and qualifications.
- Source data / important evidence: Introductory source-based description.
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Follow one request through the system.

- Current ID: `data-flow`.
- Purpose and important copy: preserve the existing data-flow explanation and qualifications.
- Source data / important evidence: `./assets/architecture/data-flow.svg`, `src/bulldog/canonicalizer.py`, `src/bulldog/profiles.py`, `src/bulldog/dispatcher.py`, `src/bulldog/engine.py`, `src/bulldog/runtime.py`, `src/bulldog/snapshot.py`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## The agent can propose more. It cannot grant itself more.

- Current ID: `authority`.
- Purpose and important copy: preserve the existing authority explanation and qualifications.
- Source data / important evidence: `src/bulldog/canonicalizer.py`, `src/bulldog/models.py`, `src/bulldog/security_domain.py`, `src/bulldog/session_guard.py`, `src/bulldog/engine.py`, `src/bulldog/dispatcher.py`, `src/bulldog/runtime.py`, `src/bulldog/advisory.py`, `src/bulldog/multiagent/system.py`, `src/bulldog/multiagent/honeytoken.py`, `src/bulldog/filesystem_manifest.py`, `src/bulldog/secure_fs.py`, `src/bulldog/snapshot.py`, `src/bulldog/malware_scanner.py`, `src/bulldog/adversary/system.py`, `src/bulldog/agent_sentinel.py`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## The kernel enforces restrictions. BULL decides what to request.

- Current ID: `kernel`.
- Purpose and important copy: preserve the existing kernel explanation and qualifications.
- Source data / important evidence: `./assets/architecture/kernel-layers.svg`, `src/bulldog/namespace_sandbox.py`, `src/bulldog/_namespace_launcher.sh`, `src/bulldog/_namespace_launcher.sh`, `src/bulldog/seccomp_policy.py`, `src/bulldog/landlock_policy.py`, `src/bulldog/resource_limits.py`, `src/bulldog/cgroup_scope.py`, `src/bulldog/workspace_limits.py`, `src/bulldog/production_gate.py`, `https://docs.kernel.org/userspace-api/seccomp_filter.html`, `https://docs.kernel.org/userspace-api/landlock.html`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Host → QEMU → guest kernel → trusted engine.

- Current ID: `microvm`.
- Purpose and important copy: preserve the existing microvm explanation and qualifications.
- Source data / important evidence: `./assets/architecture/microvm-io.svg`, `src/bulldog/microvm.py`, `microvm/guest/init`, `microvm/rootfs/build-ext4.sh`, `docs/MICROVM_INTEGRATION_REPORT.md`, `docs/MICROVM_RELEASE_STATUS.md`, `https://www.qemu.org/docs/master/system/i386/microvm.html`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: dark outer-boundary panel with nested isolation layers and case labels.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Separate channels. Separate permission checks.

- Current ID: `brokers`.
- Purpose and important copy: preserve the existing brokers explanation and qualifications.
- Source data / important evidence: `src/bulldog/dispatcher.py`, `src/bulldog/secret_broker.py`, `src/bulldog/egress_proxy.py`, `src/bulldog/socket_hardening.py`, `./assets/architecture/audit-flow.svg`, `src/bulldog/audit.py`, `src/bulldog/audit_transport.py`, `src/bulldog/anchor_service.py`, `deploy/cloudflare-audit/README.md`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: editorial heading, generous spacing and retained technical detail.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Red-team regressions, resource use and hot-path measurements.

- Current ID: `benchmarks`.
- Purpose and important copy: preserve the existing benchmarks explanation and qualifications.
- Source data / important evidence: `./assets/benchmarks/attack-pass-rate.svg`, `./assets/benchmarks/attack-latency.svg`, `./assets/benchmarks/attack-memory.svg`, `./assets/benchmarks/hotpath-throughput.svg`, `docs/BENCHMARK_20260920.md`, `./data/benchmarks/20260920/benchmark.json`, `./data/benchmarks/20260920/attack-summary.csv`, `./data/benchmarks/20260920/hotpath.csv`, `docs/PRODUCTION_EXTERNAL_AUDIT_EVIDENCE_20260920.md`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: lab-style metric tiles and unchanged charts.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Where the implementation lives.

- Current ID: `repository`.
- Purpose and important copy: preserve the existing repository explanation and qualifications.
- Source data / important evidence: `./repository.html`, `./data/repository.json`, `.github/workflows/pages.yml`, `.github/workflows/pytest.yml`, `.github/workflows/formal.yml`, `.github/workflows/microvm.yml`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: two-column generated module cards.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Implemented is not the same as certified.

- Current ID: `status`.
- Purpose and important copy: preserve the existing status explanation and qualifications.
- Source data / important evidence: `./data/verification.json`
- Current structure: long-form section with diagrams, tables or source links.
- Proposed structure: prominent evidence and limitations panels.
- Responsive behavior: stacked at narrow widths; readable tables scroll within their region.
- Interaction / motion: anchor navigation, short decorative reveal; all text visible without JavaScript.
- Files affected: site/index.html, site/styles.css, site/infrastructure.js.
- Security / accuracy: retain caveats, source links and measured scope; no new certification claims.

## Added sections

Evidence strip links separately to selected benchmark corpus, recorded KVM cases and operator-run external anchor. Architecture overview separates proposal, host-owned authority and host capabilities. Manuscript links to the unchanged supplied PDF, labeled author-review v0.2 pinned to 01cd259; not peer reviewed. Authority tree and defense stack are conceptual illustrations, not runtime telemetry. Existing benchmark ID remains unique. tools/build_site.py remains authoritative.
