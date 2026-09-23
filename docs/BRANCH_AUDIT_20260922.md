# Branch inventory and claim scope

Snapshot after `git fetch origin`, with candidate `c09629a773beb33a25599453cb785d4baa205936` and main `974eb17081e3374e99ecd35f9ebb3ef6121beefa`.

Inventoried 65 local/remote branch refs (symbolic origin/HEAD excluded). Inspected ancestry, patch-equivalence and changed-path lists for every ref. This is not execution of every historical branch or a line-by-line security review of every historical patch. No branches were deleted or merged.

Ahead/behind are relative to the candidate, not main. Squash merges mean ahead commits do not necessarily indicate missing functionality. A patch-equivalent classification excludes merge commits and does not prove semantic equivalence.

| Branch | Tip | Behind | Ahead | Classification |
|---|---|---:|---:|---|
| `design/bull-premium-site-v2` | `01cd2599a436` | 14 | 0 | ancestor |
| `feature/microvm-output-bridge` | `160b1b17d682` | 26 | 1 | divergent history; do not infer integration |
| `fix/microvm-guest-integration-r3` | `e3adc03c00e8` | 22 | 3 | divergent history; do not infer integration |
| `fix/production-validation-20260922` | `c09629a773be` | 0 | 0 | candidate |
| `hardening/microvm-audit` | `1f8e600650b4` | 28 | 4 | divergent history; do not infer integration |
| `hardening/microvm-ci` | `31cac8fe59bf` | 28 | 9 | divergent history; do not infer integration |
| `hardening/microvm-launcher` | `4d31eb433bd8` | 29 | 1 | patch-equivalent non-merge changes |
| `hardening/microvm-production` | `79a548343e87` | 28 | 12 | divergent history; do not infer integration |
| `hardening/strict-no-sockets-20260921T011646Z` | `f01871e4287b` | 22 | 4 | divergent history; do not infer integration |
| `main` | `974eb17081e3` | 6 | 0 | ancestor |
| `origin/brand/approved-b-logo-20260919` | `54cc2e0294cc` | 23 | 8 | divergent history; do not infer integration |
| `origin/branding/approved-bulldog-b-20260919` | `99d244facba2` | 23 | 3 | divergent history; do not infer integration |
| `origin/copilot/fix-132678602-1369267866-fce47232-30a3-4c95-83fc-0e490010bab0` | `67c0ce8be444` | 18 | 1 | divergent history; do not infer integration |
| `origin/design/bull-premium-site-v2` | `55f64d3c262f` | 14 | 1 | patch-equivalent non-merge changes |
| `origin/docs/site-repo-parity-20260920` | `b1ebd1777812` | 18 | 0 | ancestor |
| `origin/docs/site-repo-parity-signed-stage-20260920` | `26eede4eac40` | 18 | 1 | patch-equivalent non-merge changes |
| `origin/feat/codespace-deployment-checks-20260922` | `7c4d9da9f2e0` | 11 | 1 | patch-equivalent non-merge changes |
| `origin/feat/multiagent-system` | `85dccea506e0` | 20 | 27 | divergent history; do not infer integration |
| `origin/feat/portable-deployment-authority` | `1d558e690c93` | 10 | 2 | divergent history; do not infer integration |
| `origin/feat/publish-verified-guest-artifact` | `f62b8429a626` | 9 | 1 | patch-equivalent non-merge changes |
| `origin/feature/benchmark-evidence-and-cloudflare-20260920` | `fc0378eb3c1e` | 15 | 1 | patch-equivalent non-merge changes |
| `origin/feature/benchmark-evidence-and-cloudflare-signed-20260920` | `9f4514671745` | 15 | 1 | patch-equivalent non-merge changes |
| `origin/feature/bull-brand-story-20260919` | `a2752efb79fc` | 25 | 2 | divergent history; do not infer integration |
| `origin/feature/bull-control-dashboard-rebased-20260918` | `b44b4eda808f` | 34 | 8 | divergent history; do not infer integration |
| `origin/feature/bull-pages-live-lab-20260918` | `8a7454492b83` | 36 | 9 | divergent history; do not infer integration |
| `origin/feature/cloudflare-audit-anchor-20260920` | `f58050702cb0` | 16 | 6 | divergent history; do not infer integration |
| `origin/feature/cloudflare-audit-anchor-signed-20260920` | `b8a38e3f6abc` | 16 | 1 | divergent history; do not infer integration |
| `origin/feature/dashboard-console-ui-20260918` | `691c8603359d` | 35 | 4 | divergent history; do not infer integration |
| `origin/feature/microvm-output-bridge` | `160b1b17d682` | 26 | 1 | divergent history; do not infer integration |
| `origin/fix/architecture-film-no-public-lab-20260919` | `82157fc1666f` | 24 | 3 | divergent history; do not infer integration |
| `origin/fix/audit-anchor-user-agent` | `cdc7a640c864` | 17 | 1 | patch-equivalent non-merge changes |
| `origin/fix/audit-anchor-user-agent-signed-20260920` | `a0d443cce3e1` | 16 | 1 | patch-equivalent non-merge changes |
| `origin/fix/codespace-permission-fixtures-20260922` | `6dbcc03cb172` | 12 | 1 | patch-equivalent non-merge changes |
| `origin/fix/freshclam-permitted-paths` | `5a1f7eb460f5` | 7 | 3 | divergent history; do not infer integration |
| `origin/fix/guest-release-freshclam` | `056b4a5427ff` | 8 | 1 | patch-equivalent non-merge changes |
| `origin/fix/local-only-microvm-assets-20260919` | `52b71e68a74d` | 26 | 1 | patch-equivalent non-merge changes |
| `origin/fix/microvm-guest-integration-r3` | `45b036e94416` | 21 | 5 | divergent history; do not infer integration |
| `origin/fix/production-validation-20260922` | `c09629a773be` | 0 | 0 | candidate |
| `origin/hardening/authorization-binding-fix` | `940b3d0e5068` | 116 | 0 | ancestor |
| `origin/hardening/broker-argv-binding-v2` | `a95cb19542ea` | 96 | 5 | divergent history; do not infer integration |
| `origin/hardening/ci-main-gate` | `292918ae42ed` | 133 | 0 | ancestor |
| `origin/hardening/fail-closed-broker-argv-v2` | `131ea75f3560` | 90 | 0 | ancestor |
| `origin/hardening/human-auditable-adversarial-flags` | `5e949c97b717` | 150 | 8 | divergent history; do not infer integration |
| `origin/hardening/microvm-audit` | `1f8e600650b4` | 28 | 4 | divergent history; do not infer integration |
| `origin/hardening/microvm-audit-signed` | `7d4a0bf6b756` | 28 | 2 | divergent history; do not infer integration |
| `origin/hardening/microvm-ci` | `96be3f19167f` | 29 | 3 | divergent history; do not infer integration |
| `origin/hardening/microvm-ci-signed` | `07c14641ffcf` | 27 | 1 | patch-equivalent non-merge changes |
| `origin/hardening/microvm-launcher` | `4d31eb433bd8` | 29 | 1 | patch-equivalent non-merge changes |
| `origin/hardening/multi-agent-isolation-v1` | `87463232d2fd` | 145 | 14 | divergent history; do not infer integration |
| `origin/hardening/ollama-redteam-20260918-182423` | `19f16ed72fd2` | 30 | 1 | divergent history; do not infer integration |
| `origin/hardening/production-boundary-v1` | `6628b8796e53` | 97 | 0 | ancestor |
| `origin/hardening/production-boundary-v3` | `d55760d20e97` | 45 | 0 | ancestor |
| `origin/hardening/runtime-enforcement-fix` | `bfe799393723` | 146 | 10 | divergent history; do not infer integration |
| `origin/hardening/security-domain-audit-v2` | `b90bb6c8acfa` | 128 | 0 | ancestor |
| `origin/hardening/security-domains-v1` | `55bc3da464d1` | 135 | 0 | ancestor |
| `origin/hardening/strict-no-sockets-20260921T011646Z` | `f01871e4287b` | 22 | 4 | divergent history; do not infer integration |
| `origin/license/gpl-2-or-later-20260920` | `616d876e58d3` | 19 | 3 | divergent history; do not infer integration |
| `origin/main` | `974eb17081e3` | 6 | 0 | ancestor |
| `origin/redteam/authorization-binding-v1` | `e1d8d274dc6f` | 144 | 0 | ancestor |
| `origin/redteam/sandbox-decision-bypass-v1` | `bd0ebf170c14` | 22 | 3 | divergent history; do not infer integration |
| `origin/redteam/test-harness` | `769928609c6b` | 10 | 5 | divergent history; do not infer integration |
| `origin/release/human-approval-20260922` | `77a348526ec2` | 13 | 2 | divergent history; do not infer integration |
| `origin/site/longform-technical-20260918` | `1d5313c4769b` | 31 | 5 | divergent history; do not infer integration |
| `origin/tools/production-provision-20260920` | `7f660b3c960a` | 17 | 2 | divergent history; do not infer integration |
| `origin/tools/production-provision-signed-stage-20260920` | `a79a8fbb92ad` | 17 | 1 | patch-equivalent non-merge changes |

## Material claim distinctions

- `feature/microvm-output-bridge` contains an earlier `microvm_session.py`. Current one-shot VM evidence comes from `microvm/integration.py` and the current guest engine/protocol, not a claim that the old branch is merged verbatim.
- Earlier dashboard/live-lab/story branches contain interfaces removed from the current publication. Do not demonstrate them as supported current products.
- `origin/redteam/test-harness` adds a standalone harness with an offline mode that copies historical anchor crypto. Its helper treats any exception as rejection. Those outcomes cannot establish current implementation correctness or real isolation; use current checked-in tests with explicit expected exceptions/effects.
- Earlier runtime, domain, argv, audit and guest hardening branches overlap current modules. Current claims are mapped to current source/tests in SECURITY_CLAIMS.md, rather than inferred from branch names or commit titles.
- Local `hardening/microvm-ci` and `hardening/microvm-production` include local history worth preserving. Divergent branches were not reset to origin.
- The website `bull` and audit collector `bull-audit` are distinct Workers. A website preview pass is not a collector build pass or a firewall gate pass.

## Before answering a historical claim

Name the branch and exact commit, identify whether the mechanism exists in the current candidate, then cite a test and its environment. For an unreviewed branch-specific claim, answer “not established by this audit.” Do not claim all branches are secure or all historical work was integrated.
