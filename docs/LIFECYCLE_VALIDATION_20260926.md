# Lifecycle lab validation — 2026-09-26

## Exact scope

Validated the new lifecycle source slice in the assistant execution container,
Python 3.13.5. This was not a full checkout of BULL: outbound DNS blocked cloning.
Existing production sources were inspected through the GitHub connector.
The eight implementation/test/design files were published on
`feat/lifecycle-governance-lab-20260926` and their Git blob hashes checked against
the local tested files. The original UI and production paths were not modified.

Core source SHA-256:
`2819820a63e54ad768efad1f871e64994c1ffc11cd840d7f9e65081c3d06aba9`

## Results actually observed

| Check | Result | Meaning |
|---|---|---|
| New gate and lab tests | 56 passed | Includes authority, schema, expiry, clock rollback, replay, taint, identity quotas, descendant freeze, restart, tamper, audit failures and concurrent admission |
| Disposable walkthrough | 12/12 expected outcomes | Measured from actual local fixture execution and policy inspections, not 12 executed effects |
| Adapter calls | READ 1; PERSIST 1; REPLICATE 0 | One synthetic file read; one approved synthetic write; no protected-copy adapter invocation |
| Lineage | 3 domains frozen | Root, child and grandchild are persistently revoked |
| Owned worker | Termination confirmed | A harmless subprocess created by the lab was stopped after freeze |
| Synthetic memory file | Removed | Registered local revoker confirmed cleanup |
| Synthetic external session | Pending / unsupported | No cloud credential revoker is installed; not reported as completed |
| Audit | 28 locally authenticated events | HMAC state and event chain verified at report generation; not remotely anchored |
| Browser rendering | 4 viewports passed, 0 page errors | Offline Chromium HTML rendering at 1440x1080, 1024x900, 768x1024 and 390x844 |
| Browser interaction | Replay and audit expansion passed | Recorded-evidence navigation only; no runtime mutation |
| Overflow | None at the four tested widths | Checked document scroll width against viewport width |
| HTTP boundary | GET report 200; key/database/traversal 404; POST 405 | Real loopback requests, tested independently from offline browser rendering |

Commands:

```bash
python -m pytest -q tests/test_lifecycle_governance.py tests/test_lifecycle_lab.py
python tools/run_lifecycle_lab.py --output /tmp/bull-lifecycle-evidence
python tools/check_lifecycle_browser.py /path/to/generated/index.html
```

The optional browser check uses `set_content`, not a live Codespaces navigation.
No browser administrative policy was disabled. The standalone report uses the
existing approved repository mark when available and a text BULL fallback in the
isolated source slice; no replacement brand artwork is generated.

## Not established by this validation

The full pre-existing BULL regression suite, KVM guest execution, model behavior,
independent physical approval, external checkpoint freshness, universal resource
cleanup, hostile same-interpreter isolation, all forty threat mitigations and
complete host-wide mediation have not been qualified by these results.

A dedicated read-only-permissions GitHub workflow was added for Python 3.11/3.13
conformance and the actual fixture. Remote CI status is separate from the local
results above; consult PR #80 rather than treating this document as a live CI feed.
Do not upload fixture signing keys or state databases as CI artifacts.
