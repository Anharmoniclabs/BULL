# September 23 branch integration

All fetched branch tips are recorded in the [inventory](evidence/branch-integration-20260923.json).
The integrated software release from PR 55 is on main. This follow-up brings in
PR 29's exact approved branding, the local hardware prototype and its tested host
ApprovalGate provider, plus the standalone adversarial harness.

The harness now recognizes explicit denied ExecutionResult values, supplies an
actual authorized argv tuple, and forwards envelopes with their hop history.
Its 49 probes cover source/API behavior, not live production containment. Run
`python tools/adversarial_check.py` from the checkout. Offline mode tests a frozen
crypto fixture and is not evidence about current deployed code.

Older branch tips mostly represent already merged work, signed staging branches,
or superseded designs. Their histories remain available. In particular, the old
public dashboard execution console and earlier MicroVM output-disk adapter are
replaced by the current static publication and authenticated one-shot guest route.
They are not reintroduced into production merely to make Git ancestry uniform.

The original dirty main checkout was backed up before integration. Runtime fixes
and governed-agent files there already matched the merged software release; its
hardware files are now integrated from source with public documentation sanitized
of local device identifiers and backup locations. No private keys, local deployment
state, flashed board backups or guest images enter Git.

Hardware status and remaining physical dependencies are documented in
[HARDWARE_AUTHORITY.md](HARDWARE_AUTHORITY.md). The custom assertion verifier now
shares the normal gate and broker effect path; diagnostic firmware still cannot
sign or authorize. Existing deployment integrity manifests must be regenerated
for the changed trusted source. No hardware acceptance or stable release is implied
by integrating the prototype source.
